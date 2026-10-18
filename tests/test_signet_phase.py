"""Cold handoff/admission fault tests, with explicitly stubbed native proofs."""
import fcntl
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from simulator.signet import Campaign
from simulator.signet_phase import stage_existing_phase, admit_existing_phase, advance_phase
from tests import test_signet


class PhaseTests(unittest.TestCase):
    setUp = test_signet.SignetTests.setUp
    tearDown = test_signet.SignetTests.tearDown

    def fixture(self):
        self.new_config = {**self.config, "source_commit": "c" * 40}
        self.new_directory, self.archive = self.root / "new-phase", self.root / "old-archive"
        self.stop, self.lock, self.pid, self.first_pass = [self.root / name for name in ["STOP", "runner.lock", "runner.pid", "first-pass.json"]]
        self.stop.touch(); self.lock.touch(); self.pid.write_text("1073741824")
        self.first_pass.write_text(json.dumps({"progress": {"case_verdict": "PASS"}}))
        for actor in ["sender", "receiver"]:
            directory = self.campaign.actor_path(actor); directory.mkdir(parents=True, mode=0o700)
            values = {"server_address": self.config["ark_url"], "bitcoind_address": self.config["core_url"],
                      "bitcoind_cookiefile": self.config["core_credential"]}
            (directory / "config.toml").write_text("\n".join(key + " = " + json.dumps(value) for key, value in values.items()))
            (directory / "mnemonic").write_text("private fixture seed: never a recovery receipt")
            (directory / "wallet.sqlite").write_bytes(b"cold wallet bytes preserved")
            for path in directory.iterdir():path.chmod(0o600)
        # The pinned fake client remains at its existing test path.
        for name in ["captaind", "watchmand", "barkd"]:
            (self.binary.parent / name).write_bytes(name.encode())
        configuration = self.root / "service-config";configuration.mkdir()
        for name in ["captaind", "watchmand"]:(configuration / (name + ".toml")).write_text(name)
        manifest = self.root / "runtime-manifest.json";manifest.write_text('paired sources are explicit')
        def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
        hashes = {name:sha(configuration / (name + ".toml")) for name in ["captaind", "watchmand"]}
        from simulator.model import canonical
        self.new_config["product_config_sha256"] = hashlib.sha256(canonical(hashes).encode()).hexdigest()
        # Runtime filenames are fixed, so use a real fake client file named bark.
        client = self.binary.parent / "bark";client.write_bytes(self.binary.read_bytes())
        self.new_config["binary"] = str(client)
        self.runtime_pins = {"binary_directory":str(client.parent),
            "elf_sha256":{name:sha(client.parent / name) for name in ["bark", "barkd", "captaind", "watchmand"]},
            "elf_source":{name:("c"*40 if name in {"bark","barkd"} else "d"*40) for name in ["bark","barkd","captaind","watchmand"]},
            "configuration_directory":str(configuration),"config_hashes":hashes,
            "runtime_manifest":str(manifest),"runtime_manifest_sha256":sha(manifest)}

    def native(self, argv, **kwargs):
        from pathlib import Path
        actor = Path(argv[argv.index("--datadir") + 1]).name
        char = "1" if actor == "sender" else "2"
        if argv[-1] == "address":
            kwargs["stdout"].write(("tark1" + char * 20).encode())
            return subprocess.CompletedProcess(argv, 0)
        if "fallback-record" in argv:
            value = {"network": "signet", "mailbox_pk": "02" + char * 64,
                     "payout_address": "tb1q" + char * 40, "record_hex": char * 64,
                     "record": {"spk": "0014" + char * 40, "account_xpub": "tpubfixture" + actor,
                                "mailbox_signature": char * 128, "account_signature": char * 128}}
        else:
            value = [{"id": char * 64 + ":0", "amount_sat": 10000,
                      "user_pubkey": "02" + char * 64, "chain_anchor": char * 64 + ":0",
                      "expiry_height": 200, "state": {"type": "spendable"}}]
        kwargs["stdout"].write(json.dumps(value).encode())
        return subprocess.CompletedProcess(argv, 0)

    def stage(self):
        with patch("simulator.signet.subprocess.run", side_effect=self.native), \
             patch("simulator.signet_phase.verify_coin", return_value={"status": "PASS"}), \
             patch("simulator.signet_phase.confirmed_backing", return_value={"backing": "stubbed"}):
            return stage_existing_phase(self.campaign, self.new_directory, self.new_config, self.archive,
                                        handoff_id="checked-candidate", stop_file=self.stop, lock_file=self.lock,
                                        pid_file=self.pid, first_pass_file=self.first_pass, runtime_pins=self.runtime_pins)

    def open_new(self):
        phase = Campaign(self.new_directory, self.new_config)
        phase.core = self.campaign.core
        self.addCleanup(phase.close)
        return phase

    def test_cold_copy_preserves_wallets_original_journal_and_creates_no_fake_actions(self):
        self.fixture()
        staged = self.stage()
        self.assertEqual(staged["stage"], "STAGED_AWAITING_NATIVE_ADMISSION")
        self.assertEqual((self.new_directory / "wallets/sender/wallet.sqlite").read_bytes(), b"cold wallet bytes preserved")
        self.assertTrue((self.archive / "signet.sqlite").is_file())
        self.assertEqual((self.archive / "original-s01-first-pass.json").read_bytes(), self.first_pass.read_bytes())
        phase = self.open_new()
        self.assertEqual(phase.db.execute("SELECT count(*) FROM action").fetchone()[0], 0)
        self.assertEqual(self.campaign.config["source_commit"], "a" * 40)
        self.assertEqual(phase.config["source_commit"], "c" * 40)
        self.assertEqual((phase.actor_path("sender") / "mnemonic").stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(ValueError, "already exist"):
            self.stage()

    def test_live_runner_and_held_lock_prevent_any_wallet_read_or_copy(self):
        self.fixture()
        with patch("simulator.signet_phase.os.kill"), patch("simulator.signet.subprocess.run") as native:
            with self.assertRaisesRegex(ValueError, "still alive"):
                self.stage()
        native.assert_not_called()
        with self.lock.open("r+") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.stage()
        self.assertFalse(self.new_directory.exists())

    def test_symlink_wallet_is_not_staged(self):
        self.fixture()
        (self.campaign.actor_path("sender") / "linked-secret").symlink_to(self.first_pass)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            self.stage()
        self.assertFalse(self.new_directory.exists())

    def test_unknown_original_action_prevents_baseline_reads(self):
        self.fixture()
        with patch("simulator.signet.subprocess.run", side_effect=subprocess.TimeoutExpired("bark", 5)):
            self.campaign.execute("uncertain-old-send", "sender", "send", {"destination": "tark1111", "amount_sat": 5000})
        with patch("simulator.signet.subprocess.run") as native:
            with self.assertRaisesRegex(ValueError, "reconciliation"):
                self.stage()
        native.assert_not_called()
        self.assertEqual(self.campaign.db.execute("SELECT count(*) FROM action").fetchone()[0], 1)

    def test_candidate_admission_performs_actual_reads_and_pins_existing_config(self):
        self.fixture(); self.stage(); phase = self.open_new()
        with patch("simulator.signet.subprocess.run", side_effect=self.native) as native, \
             patch("simulator.signet_phase.verify_coin", return_value={"status": "PASS"}), \
             patch("simulator.signet_phase.confirmed_backing", return_value={"backing": "stubbed"}):
            result = admit_existing_phase(phase)
            self.assertEqual(native.call_count, 4)
            self.assertEqual(admit_existing_phase(phase), result)
            self.assertEqual(native.call_count, 4)
        self.assertEqual(result["stage"], "EXISTING_NATIVE_COHORT_ADMITTED")
        self.assertEqual(phase.db.execute("SELECT count(*) FROM action WHERE operation IN ('create','restore','send')").fetchone()[0], 0)
        with patch("simulator.signet.subprocess.run") as native:
            self.assertEqual(advance_phase(phase)["stage"], "WAITING_FOR_NEW_HEIGHT_AFTER_ADMISSION")
        native.assert_not_called()
        (phase.actor_path("sender") / "config.toml").write_text('server_address = "wrong"')
        with patch("simulator.signet.subprocess.run") as native:
            with self.assertRaisesRegex(ValueError, "configuration changed"):
                phase.execute("altered-config-read", "sender", "sync_vtxos", {})
        native.assert_not_called()

    def test_validly_shaped_changed_registration_is_not_admitted(self):
        self.fixture(); self.stage(); phase = self.open_new()
        def wrong(argv, **kwargs):
            result = self.native(argv, **kwargs)
            if "fallback-record" in argv:
                kwargs["stdout"].seek(0);value=json.loads(kwargs["stdout"].read())
                value["record"]["spk"]="0014"+"f"*40
                kwargs["stdout"].seek(0);kwargs["stdout"].truncate();kwargs["stdout"].write(json.dumps(value).encode())
            return result
        with patch("simulator.signet.subprocess.run", side_effect=wrong):
            with self.assertRaisesRegex(ValueError, "registration changed"):
                admit_existing_phase(phase)
        self.assertIsNone(phase.db.execute("SELECT value FROM meta WHERE key='phase_admitted'").fetchone())
        with self.assertRaisesRegex(ValueError, "admission required"):
            advance_phase(phase)

    def test_changed_coin_value_is_not_admitted(self):
        self.fixture();self.stage();phase=self.open_new()
        def wrong(argv, **kwargs):
            result=self.native(argv,**kwargs)
            if "vtxos" in argv:
                kwargs["stdout"].seek(0);value=json.loads(kwargs["stdout"].read());value[0]["amount_sat"]+=1
                kwargs["stdout"].seek(0);kwargs["stdout"].truncate();kwargs["stdout"].write(json.dumps(value).encode())
            return result
        with patch("simulator.signet.subprocess.run",side_effect=wrong):
            with self.assertRaisesRegex(ValueError,"coin cohort changed"):
                admit_existing_phase(phase)

    def test_failed_post_send_accounting_never_repeats_that_phase_payment(self):
        self.fixture();self.stage();phase=self.open_new()
        with patch("simulator.signet.subprocess.run",side_effect=self.native), \
             patch("simulator.signet_phase.verify_coin",return_value={"status":"PASS"}), \
             patch("simulator.signet_phase.confirmed_backing",return_value={"backing":"stubbed"}):
            admit_existing_phase(phase)
        phase.core.info["blocks"]+=1
        dispatched=[]
        def unchanged(argv,**kwargs):
            if "send" in argv:dispatched.append(argv)
            return self.native(argv,**kwargs)
        with patch("simulator.signet.subprocess.run",side_effect=unchanged), \
             patch("simulator.signet_traffic.confirmed_backing",return_value={"backing":"stubbed"}):
            for unused in range(2):
                with self.assertRaisesRegex(RuntimeError,"conservation/backing"):
                    advance_phase(phase)
        self.assertEqual(len(dispatched),1)
        self.assertEqual(phase.db.execute("SELECT actor FROM action WHERE operation='send'").fetchone()[0],"receiver")

    def test_changed_server_executable_blocks_even_candidate_wallet_reads(self):
        self.fixture();self.stage();phase=self.open_new()
        (self.root / "captaind").write_bytes(b"different server")
        with patch("simulator.signet.subprocess.run") as native:
            with self.assertRaisesRegex(ValueError,"executable changed"):
                admit_existing_phase(phase)
        native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
