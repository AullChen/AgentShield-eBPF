import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import container_launcher as launcher


class ContainerArgumentsTests(unittest.TestCase):
    def test_fixed_isolation_and_no_inherited_channels(self):
        args = launcher.create_arguments("sha256:" + "a" * 64, Path("/approved"), Path("/trusted/init"), Path("/private/gateway.sock"))
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--cgroupns=host", "--no-healthcheck", "--restart=no", "--pull=never"):
            self.assertIn(flag, args)
        self.assertEqual(args.count("--mount"), 3)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--env", args)
        self.assertNotIn("--publish", args)
        self.assertNotIn("--rm", args)  # finish must precede cleanup
        self.assertEqual(launcher.ContainerTask._argv("inspect", "id")[:2], ["/usr/bin/docker", "--host=unix:///var/run/docker.sock"])

    def test_mutable_images_rejected(self):
        for image in ("python:latest", "trusted@sha256:bad", "sha256:" + "a" * 63):
            with self.assertRaises(ValueError):
                launcher.create_arguments(image, Path("/project"), Path("/init"), Path("/socket"))

    def test_resource_launch_rejected_without_linux_root(self):
        if sys.platform != "linux":
            with self.assertRaises(ValueError):
                launcher.ContainerTask(image="", project="", init="", gateway="", cgroup_parent="", command=[])

    def test_cgroupfs_must_be_readonly_and_present(self):
        ro = "31 22 0:27 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup rw\n"
        self.assertTrue(launcher.readonly_cgroupfs(ro))
        self.assertFalse(launcher.readonly_cgroupfs(ro.replace("ro,nosuid", "rw,nosuid")))
        self.assertFalse(launcher.readonly_cgroupfs(ro + ro.replace("ro,nosuid", "rw,nosuid")))
        self.assertFalse(launcher.readonly_cgroupfs(""))

    def test_init_cannot_be_replaced_through_writable_ancestor(self):
        trusted = Mock(st_uid=0, st_mode=0o755)
        with patch.object(Path, "stat", return_value=trusted):
            launcher.verify_init_ancestors(Path("/opt/agentshield/init"))
        writable = Mock(st_uid=0, st_mode=0o777)
        with patch.object(Path, "stat", return_value=writable):
            with self.assertRaises(ValueError):
                launcher.verify_init_ancestors(Path("/tmp/init"))


if __name__ == "__main__":
    unittest.main()
