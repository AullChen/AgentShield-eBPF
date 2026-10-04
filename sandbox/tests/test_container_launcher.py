import importlib.util
from pathlib import Path
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
