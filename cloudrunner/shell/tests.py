__author__ = 'Ivelin Slavov'

from cloudrunner.tests.base import BaseTestCase
from cloudrunner import CONFIG_SHELL_LOC
from cloudrunner.util.config import Config
from cloudrunner.plugins.transport.zmq_transport import ZmqCliTransport



class TestController(BaseTestCase):

    def test_run_local(self):
        transport = ZmqCliTransport()
        transport.configure(overwrite=True)

        CONFIG = Config(CONFIG_SHELL_LOC)
        from cloudrunner.shell.api import CloudRunner
        cr = CloudRunner.from_config(CONFIG)
        async_res = cr.run_local("echo 123")

        it = async_res.iter()
        pipe_msg = next(it)

        self.assertEqual(pipe_msg.node, "localhost")
        self.assertEqual(pipe_msg.stdout, "123\n")

        cr.close()