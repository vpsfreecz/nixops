# -*- coding: utf-8 -*-
import os
import sys
import nixops.util

from nixops.backends import MachineDefinition, MachineState
from nixops.util import attr_property, create_key_pair


class DumbDefinition(MachineDefinition):
    """Definition of a dumb machine."""

    @classmethod
    def get_type(cls):
        return "dumb"

    def __init__(self, xml, config):
        MachineDefinition.__init__(self, xml, config)
        self._target_host = xml.find("attrs/attr[@name='targetHost']/string").get("value")

        public_ipv4 = xml.find("attrs/attr[@name='publicIPv4']/string")
        self._public_ipv4 = None if public_ipv4 is None else public_ipv4.get("value")

class DumbState(MachineState):
    """State of a dumb machine."""

    @classmethod
    def get_type(cls):
        return "dumb"

    target_host = nixops.util.attr_property("targetHost", None)
    public_ipv4 = nixops.util.attr_property("publicIpv4", None)

    def __init__(self, depl, name, id):
        MachineState.__init__(self, depl, name, id)

    @property
    def resource_id(self):
        return self.vm_id

    def get_physical_spec(self):
        return {}

    def create(self, defn, check, allow_reboot, allow_recreate):
        assert isinstance(defn, DumbDefinition)
        self.set_common_state(defn)
        self.target_host = defn._target_host
        self.public_ipv4 = defn._public_ipv4

    def switch_to_configuration(self, method, sync, command=None):
        res = super(DumbState, self).switch_to_configuration(method, sync, command)
        return res

    def get_ssh_name(self):
        assert self.target_host
        return self.target_host

    def get_ssh_flags(self, *args, **kwargs):
        super_state_flags = super(DumbState, self).get_ssh_flags(*args, **kwargs)
        if self.vm_id and self.cur_toplevel:
            return super_state_flags
        return super_state_flags

    def _check(self, res):
        if not self.vm_id:
            res.exists = False
            return
        res.exists = True
        res.is_up = nixops.util.ping_tcp_port(self.target_host, self.ssh_port)
        if res.is_up:
            MachineState._check(self, res)

    def destroy(self, wipe=False):
        # No-op; just forget about the machine.
        return True
