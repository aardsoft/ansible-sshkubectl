# Copyright (c) 2015-2025, Austin Hyde (@austinhyde)
from __future__ import (absolute_import, division, print_function)

import json
import os
import os.path
import shlex
import shutil
import subprocess
from packaging import version

from ansible import __version__ as ansible_version
from ansible.plugins.connection.ssh import BUFSIZE, Connection as SSHConnection
from ansible.errors import AnsibleError, AnsibleFileNotFound
from ansible.module_utils._text import to_text, to_bytes
from ansible.module_utils.six.moves import shlex_quote
from ansible.plugins.loader import get_shell_plugin
from ansible.parsing.yaml.loader import AnsibleLoader
from contextlib import contextmanager

__metaclass__ = type

MIN_ANSIBLE_VERSION = '2.11.3'

DOCUMENTATION = '''
    connection: sshkubectl
    short_description: connect via ssh client binary to kubectll
    description:
        - This connection plugin allows ansible to communicate to the target machines via normal ssh command line.
    author: Austin Hyde (@austinhyde)
    version_added: historical
    options:
      kubectl_pod:
        description:
          - Pod name.
          - Required when the host name does not match pod name.
        default: ''
        vars:
          - name: ansible_kubectl_pod
        env:
          - name: K8S_AUTH_POD
      kubectl_container:
        description:
          - Container name.
          - Required when a pod contains more than one container.
        default: ''
        vars:
          - name: ansible_kubectl_container
        env:
          - name: K8S_AUTH_CONTAINER
      kubectl_namespace:
        description:
          - The namespace of the pod
        default: ''
        vars:
          - name: ansible_kubectl_namespace
        env:
          - name: K8S_AUTH_NAMESPACE
      kubectl_extra_args:
        description:
          - Extra arguments to pass to the kubectl command line.
          - Please be aware that this passes information directly on the command line and it could expose sensitive data.
        default: ''
        vars:
          - name: ansible_kubectl_extra_args
        env:
          - name: K8S_AUTH_EXTRA_ARGS
      kubectl_local_env_vars:
        description:
          - Local enviromantal variable to be passed locally to the kubectl command line.
          - Please be aware that this passes information directly on the command line and it could expose sensitive data.
        default: {}
        type: dict
        version_added: 3.1.0
        vars:
          - name: ansible_kubectl_local_env_vars
      kubectl_kubeconfig:
        description:
          - Path to a kubectl config file. Defaults to I(~/.kube/config)
          - The configuration can be provided as dictionary. Added in version 2.4.0.
        default: ''
        vars:
          - name: ansible_kubectl_kubeconfig
          - name: ansible_kubectl_config
        env:
          - name: K8S_AUTH_KUBECONFIG
      kubectl_context:
        description:
          - The name of a context found in the K8s config file.
        default: ''
        vars:
          - name: ansible_kubectl_context
        env:
          - name: K8S_AUTH_CONTEXT
      kubectl_host:
        description:
          - URL for accessing the API.
        default: ''
        vars:
          - name: ansible_kubectl_host
          - name: ansible_kubectl_server
        env:
          - name: K8S_AUTH_HOST
          - name: K8S_AUTH_SERVER
      kubectl_username:
        description:
          - Provide a username for authenticating with the API.
        default: ''
        vars:
          - name: ansible_kubectl_username
          - name: ansible_kubectl_user
        env:
          - name: K8S_AUTH_USERNAME
      kubectl_password:
        description:
          - Provide a password for authenticating with the API.
          - Please be aware that this passes information directly on the command line and it could expose sensitive data.
            We recommend using the file based authentication options instead.
        default: ''
        vars:
          - name: ansible_kubectl_password
        env:
          - name: K8S_AUTH_PASSWORD
      kubectl_token:
        description:
          - API authentication bearer token.
          - Please be aware that this passes information directly on the command line and it could expose sensitive data.
            We recommend using the file based authentication options instead.
        vars:
          - name: ansible_kubectl_token
          - name: ansible_kubectl_api_key
        env:
          - name: K8S_AUTH_TOKEN
          - name: K8S_AUTH_API_KEY
      client_cert:
        description:
          - Path to a certificate used to authenticate with the API.
        default: ''
        vars:
          - name: ansible_kubectl_cert_file
          - name: ansible_kubectl_client_cert
        env:
          - name: K8S_AUTH_CERT_FILE
        aliases: [ kubectl_cert_file ]
      client_key:
        description:
          - Path to a key file used to authenticate with the API.
        default: ''
        vars:
          - name: ansible_kubectl_key_file
          - name: ansible_kubectl_client_key
        env:
          - name: K8S_AUTH_KEY_FILE
        aliases: [ kubectl_key_file ]
      ca_cert:
        description:
          - Path to a CA certificate used to authenticate with the API.
        default: ''
        vars:
          - name: ansible_kubectl_ssl_ca_cert
          - name: ansible_kubectl_ca_cert
        env:
          - name: K8S_AUTH_SSL_CA_CERT
        aliases: [ kubectl_ssl_ca_cert ]
      validate_certs:
        description:
          - Whether or not to verify the API server's SSL certificate. Defaults to I(true).
        default: ''
        vars:
          - name: ansible_kubectl_verify_ssl
          - name: ansible_kubectl_validate_certs
        env:
          - name: K8S_AUTH_VERIFY_SSL
        aliases: [ kubectl_verify_ssl ]
      host:
          description: Hostname/ip to connect to.
          default: inventory_hostname
          vars:
               - name: inventory_hostname
               - name: ansible_host
               - name: ansible_ssh_host
      host_key_checking:
          description: Determines if ssh should check host keys
          type: boolean
          ini:
              - section: defaults
                key: 'host_key_checking'
              - section: ssh_connection
                key: 'host_key_checking'
                version_added: '2.5'
          env:
              - name: ANSIBLE_HOST_KEY_CHECKING
              - name: ANSIBLE_SSH_HOST_KEY_CHECKING
                version_added: '2.5'
          vars:
              - name: ansible_host_key_checking
                version_added: '2.5'
              - name: ansible_ssh_host_key_checking
                version_added: '2.5'
      password:
          description: Authentication password for the C(remote_user). Can be supplied as CLI option.
          vars:
              - name: ansible_password
              - name: ansible_ssh_pass
      sshpass_prompt:
          description: Password prompt that sshpass should search for. Supported by sshpass 1.06 and up
          default: ''
          ini:
              - section: 'ssh_connection'
                key: 'sshpass_prompt'
          env:
              - name: ANSIBLE_SSHPASS_PROMPT
          vars:
              - name: ansible_sshpass_prompt
          version_added: '2.10'
      ssh_args:
          description: Arguments to pass to all ssh cli tools
          default: '-C -o ControlMaster=auto -o ControlPersist=60s'
          ini:
              - section: 'ssh_connection'
                key: 'ssh_args'
          env:
              - name: ANSIBLE_SSH_ARGS
          vars:
              - name: ansible_ssh_args
                version_added: '2.7'
      ssh_common_args:
          description: Common extra args for all ssh CLI tools
          ini:
              - section: 'ssh_connection'
                key: 'ssh_common_args'
                version_added: '2.7'
          env:
              - name: ANSIBLE_SSH_COMMON_ARGS
                version_added: '2.7'
          vars:
              - name: ansible_ssh_common_args
      ssh_executable:
          default: ssh
          description:
            - This defines the location of the ssh binary. It defaults to ``ssh`` which will use the first ssh binary available in $PATH.
            - This option is usually not required, it might be useful when access to system ssh is restricted,
              or when using ssh wrappers to connect to remote hosts.
          env: [{name: ANSIBLE_SSH_EXECUTABLE}]
          ini:
          - {key: ssh_executable, section: ssh_connection}
          #const: ANSIBLE_SSH_EXECUTABLE
          version_added: "2.2"
          vars:
              - name: ansible_ssh_executable
                version_added: '2.7'
      sftp_executable:
          default: sftp
          description:
            - This defines the location of the sftp binary. It defaults to ``sftp`` which will use the first binary available in $PATH.
          env: [{name: ANSIBLE_SFTP_EXECUTABLE}]
          ini:
          - {key: sftp_executable, section: ssh_connection}
          version_added: "2.6"
          vars:
              - name: ansible_sftp_executable
                version_added: '2.7'
      scp_executable:
          default: scp
          description:
            - This defines the location of the scp binary. It defaults to `scp` which will use the first binary available in $PATH.
          env: [{name: ANSIBLE_SCP_EXECUTABLE}]
          ini:
          - {key: scp_executable, section: ssh_connection}
          version_added: "2.6"
          vars:
              - name: ansible_scp_executable
                version_added: '2.7'
      scp_extra_args:
          description: Extra exclusive to the ``scp`` CLI
          vars:
              - name: ansible_scp_extra_args
          env:
            - name: ANSIBLE_SCP_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: scp_extra_args
              section: ssh_connection
              version_added: '2.7'
      sftp_extra_args:
          description: Extra exclusive to the ``sftp`` CLI
          vars:
              - name: ansible_sftp_extra_args
          env:
            - name: ANSIBLE_SFTP_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: sftp_extra_args
              section: ssh_connection
              version_added: '2.7'
      ssh_extra_args:
          description: Extra exclusive to the 'ssh' CLI
          vars:
              - name: ansible_ssh_extra_args
          env:
            - name: ANSIBLE_SSH_EXTRA_ARGS
              version_added: '2.7'
          ini:
            - key: ssh_extra_args
              section: ssh_connection
              version_added: '2.7'
      reconnection_retries:
          description: Number of attempts to connect.
          default: 0
          type: integer
          env:
            - name: ANSIBLE_SSH_RETRIES
          ini:
            - section: connection
              key: retries
            - section: ssh_connection
              key: retries
          vars:
            - name: ansible_ssh_retries
              version_added: '2.7'
      port:
          description: Remote port to connect to.
          type: int
          ini:
            - section: defaults
              key: remote_port
          env:
            - name: ANSIBLE_REMOTE_PORT
          vars:
            - name: ansible_port
            - name: ansible_ssh_port
      remote_user:
          description:
              - User name with which to login to the remote server, normally set by the remote_user keyword.
              - If no user is supplied, Ansible will let the ssh client binary choose the user as it normally
          ini:
            - section: defaults
              key: remote_user
          env:
            - name: ANSIBLE_REMOTE_USER
          vars:
            - name: ansible_user
            - name: ansible_ssh_user
      pipelining:
          default: ANSIBLE_PIPELINING
          description:
            - Pipelining reduces the number of SSH operations required to execute a module on the remote server,
              by executing many Ansible modules without actual file transfer.
            - This can result in a very significant performance improvement when enabled.
            - However this conflicts with privilege escalation (become).
              For example, when using sudo operations you must first disable 'requiretty' in the sudoers file for the target hosts,
              which is why this feature is disabled by default.
          env:
            - name: ANSIBLE_PIPELINING
            #- name: ANSIBLE_SSH_PIPELINING
          ini:
            - section: defaults
              key: pipelining
            #- section: ssh_connection
            #  key: pipelining
          type: boolean
          vars:
            - name: ansible_pipelining
            - name: ansible_ssh_pipelining
      private_key_file:
          description:
              - Path to private key file to use for authentication
          ini:
            - section: defaults
              key: private_key_file
          env:
            - name: ANSIBLE_PRIVATE_KEY_FILE
          vars:
            - name: ansible_private_key_file
            - name: ansible_ssh_private_key_file

      control_path:
        description:
          - This is the location to save ssh's ControlPath sockets, it uses ssh's variable substitution.
          - Since 2.3, if null, ansible will generate a unique hash. Use `%(directory)s` to indicate where to use the control dir path setting.
        env:
          - name: ANSIBLE_SSH_CONTROL_PATH
        ini:
          - key: control_path
            section: ssh_connection
        vars:
          - name: ansible_control_path
            version_added: '2.7'
      control_path_dir:
        default: ~/.ansible/cp
        description:
          - This sets the directory to use for ssh control path if the control path setting is null.
          - Also, provides the `%(directory)s` variable for the control path setting.
        env:
          - name: ANSIBLE_SSH_CONTROL_PATH_DIR
        ini:
          - section: ssh_connection
            key: control_path_dir
        vars:
          - name: ansible_control_path_dir
            version_added: '2.7'
      sftp_batch_mode:
        default: 'yes'
        description: 'TODO: write it'
        env: [{name: ANSIBLE_SFTP_BATCH_MODE}]
        ini:
        - {key: sftp_batch_mode, section: ssh_connection}
        type: bool
        vars:
          - name: ansible_sftp_batch_mode
            version_added: '2.7'
      ssh_transfer_method:
        default: smart
        description:
            - "Preferred method to use when transferring files over ssh"
            - Setting to 'smart' (default) will try them in order, until one succeeds or they all fail
            - Using 'piped' creates an ssh pipe with ``dd`` on either side to copy the data
        choices: ['sftp', 'scp', 'piped', 'smart']
        env: [{name: ANSIBLE_SSH_TRANSFER_METHOD}]
        ini:
            - {key: transfer_method, section: ssh_connection}
        vars:
            - name: ansible_ssh_transfer_method
              version_added: '2.12'
      scp_if_ssh:
        default: smart
        description:
          - "Prefered method to use when transfering files over ssh"
          - When set to smart, Ansible will try them until one succeeds or they all fail
          - If set to True, it will force 'scp', if False it will use 'sftp'
        env: [{name: ANSIBLE_SCP_IF_SSH}]
        ini:
        - {key: scp_if_ssh, section: ssh_connection}
        vars:
          - name: ansible_scp_if_ssh
            version_added: '2.7'
      use_tty:
        version_added: '2.5'
        default: 'yes'
        description: add -tt to ssh commands to force tty allocation
        env: [{name: ANSIBLE_SSH_USETTY}]
        ini:
        - {key: usetty, section: ssh_connection}
        type: bool
        vars:
          - name: ansible_ssh_use_tty
            version_added: '2.7'
      pkcs11_provider:
        version_added: '2.12'
        default: ''
        description:
          - PKCS11 SmartCard provider such as opensc, example: /usr/local/lib/opensc-pkcs11.so
          - Requires sshpass version 1.06+, sshpass must support the -P option.
        env: [{name: ANSIBLE_PKCS11_PROVIDER}]
        ini:
          - {key: pkcs11_provider, section: ssh_connection}
        vars:
          - name: ansible_ssh_pkcs11_provider
      timeout:
        default: 10
        description:
            - This is the default ammount of time we will wait while establishing an ssh connection
            - It also controls how long we can wait to access reading the connection once established (select on the socket)
        env:
            - name: ANSIBLE_TIMEOUT
            - name: ANSIBLE_SSH_TIMEOUT
              version_added: '2.11'
        ini:
            - key: timeout
              section: defaults
            - key: timeout
              section: ssh_connection
              version_added: '2.11'
        vars:
            - name: ansible_ssh_timeout
              version_added: '2.11'
        cli:
            - name: timeout
        type: integer
'''

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


CONNECTION_TRANSPORT = "sshkubectl"

CONNECTION_OPTIONS = {
    "kubectl_container": "-c",
    "kubectl_namespace": "-n",
    "kubectl_kubeconfig": "--kubeconfig",
    "kubectl_context": "--context",
    "kubectl_host": "--server",
    "kubectl_username": "--username",
    "kubectl_password": "--password",
    "client_cert": "--client-certificate",
    "client_key": "--client-key",
    "ca_cert": "--certificate-authority",
    "validate_certs": "--insecure-skip-tls-verify",
    "kubectl_token": "--token",
}

# HACK: Ansible core does classname-based validation checks, to ensure connection plugins inherit directly from a class
# named "ConnectionBase". This intermediate class works around this limitation.
class ConnectionBase(SSHConnection):
    pass


class Connection(ConnectionBase):
    ''' ssh based connections '''

    transport = CONNECTION_TRANSPORT
    connection_options = CONNECTION_OPTIONS
    documentation = DOCUMENTATION
    has_pipelining = True
    #transport_cmd = None
    # we probably should look that up on the remote host
    transport_cmd = "kubectl"

    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(*args, **kwargs)
        # self.host == jailname@jailhost
        self.inventory_hostname = self.host
        # TODO: we should support both kubectl_pod and the @ notation
        self.jailspec, self.host = self.host.split('@', 1)
        # self.jailspec == jailname
        # self.host == jailhost
        # this way SSHConnection parent class uses the jailhost as the SSH remote host

        # jail information loaded on first use by match_jail
        self.jid = None
        self.jname = None
        self.jpath = None
        self.connector = None
        self._file_to_delete = None

        if version.parse(ansible_version) < version.parse(MIN_ANSIBLE_VERSION):
            raise AnsibleError("sshkubectl needs at least ansible version " + MIN_ANSIBLE_VERSION)
        # logging.warning(self._play_context.connection)

    # we probably want to adapt this to discover/verify containers and pods
    def match_jail(self):
        if self.jid is None:
            code, stdout, stderr = self._kubectlhost_command("jls -q jid name host.hostname path")
            if code != 0:
                display.vvv("JLS stdout: %s" % stdout)
                raise AnsibleError("jls returned non-zero!")

            lines = stdout.strip().split(b'\n')
            found = False
            for line in lines:
                if line.strip() == '':
                    break

                jid, name, hostname, path = to_text(line).strip().split()
                if name == self.jailspec or hostname == self.jailspec:
                    self.jid = jid
                    self.jname = name
                    self.jpath = path
                    found = True
                    break

            if not found:
                raise AnsibleError("failed to find a jail with name or hostname of '%s'" % self.jailspec)

    def get_jail_connector(self):
        if self.connector is None:
            code, _, _ = self._kubectlhost_command("which -s kubectl")
            if code != 0:
                self.connector = 'jexec'
            else:
                self.connector = 'jailme'
        return self.connector

    def _strip_sudo(self, executable, cmd):
        # cmd looks like:
        #     sudo -H -S -n  -u root /bin/sh -c 'echo BECOME-SUCCESS-hnjapeqklmbeniylaoledvqttgvyefbd ; test -e /usr/local/bin/python || ( pkg install -y python )'
        # or
        #     /bin/sh -c 'sudo -H -S -n  -u root /bin/sh -c '"'"'echo BECOME-SUCCESS-xuaumtxycchjfekyxlbykjbqxosupbpd ; /usr/local/bin/python2.7 /root/.ansible/tmp/ansible-tmp-1629053721.2637851-12131-255051228590176/AnsiballZ_pkgng.py'"'"''

        # we need to extract just:
        #     test -e /usr/local/bin/python || ( pkg install -y python )
        # or
        #     /usr/local/bin/python2.7 /root/.ansible/tmp/ansible-tmp-1629053721.2637851-12131-255051228590176/AnsiballZ_pkgng.py

        # to do this, we peel back successive command invocations
        words = shlex.split(cmd)
        while words[0] == executable or words[0] == 'sudo':
            cmd = words[-1]
            words = shlex.split(cmd)

        # after, cmd is:
        #    echo BECOME-SUCCESS-hnjapeqklmbeniylaoledvqttgvyefbd ; test -e /usr/local/bin/python || ( pkg install -y python )
        # or:
        #    echo BECOME-SUCCESS-xuaumtxycchjfekyxlbykjbqxosupbpd ; /usr/local/bin/python2.7 /root/.ansible/tmp/ansible-tmp-1629053721.2637851-12131-255051228590176/AnsiballZ_pkgng.py

        # drop first command
        cmd = cmd.split(' ; ', 1)[1]

        return cmd

    def _strip_sleep(self, cmd):
        # Get the command without sleep
        cmd = cmd.split(' && sleep 0', 1)[0]
        # Add back trailing quote
        cmd = '%s%s' % (cmd, "'")
        return cmd

    def _kubectlhost_command(self, cmd):
        return super(Connection, self).exec_command(cmd, in_data=None, sudoable=True)

    ### adapted/copied from kubectl.py
    def _build_exec_cmd(self, cmd):
        """Build the local kubectl exec command to run cmd on remote_host"""
        local_cmd = [self.transport_cmd]
        censored_local_cmd = [self.transport_cmd]

        # Build command options based on doc string
        doc_yaml = AnsibleLoader(self.documentation).get_single_data()
        for key in doc_yaml.get("options"):
            if key.endswith("verify_ssl") and self.get_option(key) != "":
                # Translate verify_ssl to skip_verify_ssl, and output as string
                skip_verify_ssl = not self.get_option(key)
                local_cmd.append(
                    "{0}={1}".format(
                        self.connection_options[key], str(skip_verify_ssl).lower()
                    )
                )
                censored_local_cmd.append(
                    "{0}={1}".format(
                        self.connection_options[key], str(skip_verify_ssl).lower()
                    )
                )
            elif key.endswith("kubeconfig") and self.get_option(key) != "":
                kubeconfig_path = self.get_option(key)
                if isinstance(kubeconfig_path, dict):
                    fd, tmpfile = tempfile.mkstemp()
                    with os.fdopen(fd, "w") as fp:
                        json.dump(kubeconfig_path, fp)
                    kubeconfig_path = tmpfile
                    self._file_to_delete = tmpfile

                cmd_arg = self.connection_options[key]
                local_cmd += [cmd_arg, kubeconfig_path]
                censored_local_cmd += [cmd_arg, kubeconfig_path]
            elif (
                not key.endswith("container")
                and self.get_option(key)
                and self.connection_options.get(key)
            ):
                cmd_arg = self.connection_options[key]
                local_cmd += [cmd_arg, self.get_option(key)]
                # Redact password and token from console log
                if key.endswith(("_token", "_password")):
                    censored_local_cmd += [cmd_arg, "********"]
                else:
                    censored_local_cmd += [cmd_arg, self.get_option(key)]

        extra_args_name = "kubectl_extra_args".format(self.transport)
        if self.get_option(extra_args_name):
            local_cmd += self.get_option(extra_args_name).split(" ")
            censored_local_cmd += self.get_option(extra_args_name).split(" ")

        pod = self.get_option("kubectl_pod".format(self.transport))
        if not pod:
            pod = self._play_context.remote_addr
        # -i is needed to keep stdin open which allows pipelining to work
        local_cmd += ["exec", "-i", pod]
        censored_local_cmd += ["exec", "-i", pod]

        # if the pod has more than one container, then container is required
        container_arg_name = "kubectl_container".format(self.transport)
        if self.get_option(container_arg_name):
            local_cmd += ["-c", self.get_option(container_arg_name)]
            censored_local_cmd += ["-c", self.get_option(container_arg_name)]

        local_cmd += ["--"] + cmd
        censored_local_cmd += ["--"] + cmd

        return local_cmd, censored_local_cmd

    ### adapted/copied from kubectl.py
    def delete_temporary_file(self):
        if self._file_to_delete is not None:
            os.remove(self._file_to_delete)
            self._file_to_delete = None

    ### adapted/copied from kubectl.py
    def _local_env(self):
        """Return a dict of local environment variables to pass to the kubectl command"""
        local_env = {}
        local_local_env_vars_name = "kubectl_local_env_vars".format(self.transport)
        local_env_vars = self.get_option(local_local_env_vars_name)
        if local_env_vars:
            if isinstance(local_env_vars, dict):
                local_env_vars = json.dumps(local_env_vars)
            local_env = os.environ.copy()
            local_env.update(json.loads(local_env_vars))
            return local_env
        return None

    ### adapted/copied from kubectl.py
    def _connect(self, port=None):
        """Connect to the container. Nothing to do"""
        super(Connection, self)._connect()
        if not self._connected:
            display.vvv(
                "ESTABLISH {0} CONNECTION".format(self.transport),
                host=self._play_context.remote_addr,
            )
            self._connected = True

    ### adapted/copied from kubectl.py
    def _prefix_login_path(self, remote_path):
        """Make sure that we put files into a standard path

        If a path is relative, then we need to choose where to put it.
        ssh chooses $HOME but we aren't guaranteed that a home dir will
        exist in any given chroot.  So for now we're choosing "/" instead.
        This also happens to be the former default.

        Can revisit using $HOME instead if it's a problem
        """
        if not remote_path.startswith(os.path.sep):
            remote_path = os.path.join(os.path.sep, remote_path)
        return os.path.normpath(remote_path)

    def exec_command(self, cmd, in_data=None, sudoable=False):
        ''' run a command in the jail '''

        slpcmd = False

        if '&& sleep 0' in cmd:
            slpcmd = True
            cmd = self._strip_sleep(cmd)

        # TODO, this probably was just needed for jails
        if 'sudo' in cmd:
            cmd = self._strip_sudo(executable, cmd)

        self.set_option('host', self.host)

        cmd = shlex.quote(cmd)
        local_cmd, censored_local_cmd = self._build_exec_cmd(
            [self._play_context.executable, "-c", cmd]
        )

        local_cmd = ' '.join(local_cmd)

        if slpcmd:
            local_cmd = '%s %s' % (local_cmd, '&& sleep 0')
        else:
            local_cmd = '%s' % (local_cmd)

        return super(Connection, self).exec_command(local_cmd, in_data, True)

    @contextmanager
    def tempfile(self):
        code, stdout, stderr = self._kubectlhost_command('mktemp')
        if code != 0:
            raise AnsibleError("failed to make temp file:\n%s\n%s" % (stdout, stderr))
        tmp = to_text(stdout.strip().split(b'\n')[-1])

        code, stdout, stderr = self._kubectlhost_command(' '.join(['chmod 0644', tmp]))
        if code != 0:
            raise AnsibleError("failed to make temp file %s world readable:\n%s\n%s" % (tmp, stdout, stderr))

        yield tmp

        code, stdout, stderr = self._kubectlhost_command(' '.join(['rm', tmp]))
        if code != 0:
            raise AnsibleError("failed to remove temp file %s:\n%s\n%s" % (tmp, stdout, stderr))

    ### adapted/copied from kubectl.py
    def _put_file(self, in_path, out_path):
        """Transfer a file from local to the container"""
        super(Connection, self).put_file(in_path, out_path)
        display.vvv(
            "PUT %s TO %s" % (in_path, out_path), host=self._play_context.remote_addr
        )

        out_path = self._prefix_login_path(out_path)
        if not os.path.exists(to_bytes(in_path, errors="surrogate_or_strict")):
            raise AnsibleFileNotFound("file or module does not exist: %s" % in_path)

        out_path = shlex_quote(out_path)
        # kubectl doesn't have native support for copying files into
        # running containers, so we use kubectl exec to implement this
        with open(to_bytes(in_path, errors="surrogate_or_strict"), "rb") as in_file:
            if not os.fstat(in_file.fileno()).st_size:
                count = " count=0"
            else:
                count = ""
            args, dummy = self._build_exec_cmd(
                [
                    self._play_context.executable,
                    "-c",
                    "dd of=%s bs=%s%s && sleep 0" % (out_path, BUFSIZE, count),
                ]
            )
            args = [to_bytes(i, errors="surrogate_or_strict") for i in args]
            try:
                p = subprocess.Popen(
                    args,
                    stdin=in_file,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=self._local_env(),
                )
            except OSError:
                raise AnsibleError(
                    "kubectl connection requires dd command in the container to put files"
                )
            stdout, stderr = p.communicate()
            self.delete_temporary_file()

            if p.returncode != 0:
                raise AnsibleError(
                    "failed to transfer file %s to %s:\n%s\n%s"
                    % (in_path, out_path, stdout, stderr)
                )

    ### adapted/copied from kubectl.py
    def _fetch_file(self, in_path, out_path):
        """Fetch a file from container to local."""
        super(Connection, self).fetch_file(in_path, out_path)
        display.vvv(
            "FETCH %s TO %s" % (in_path, out_path), host=self._play_context.remote_addr
        )

        in_path = self._prefix_login_path(in_path)
        out_dir = os.path.dirname(out_path)

        # kubectl doesn't have native support for fetching files from
        # running containers, so we use kubectl exec to implement this
        args, dummy = self._build_exec_cmd(
            [self._play_context.executable, "-c", "dd if=%s bs=%s" % (in_path, BUFSIZE)]
        )
        args = [to_bytes(i, errors="surrogate_or_strict") for i in args]
        actual_out_path = os.path.join(out_dir, os.path.basename(in_path))
        with open(
            to_bytes(actual_out_path, errors="surrogate_or_strict"), "wb"
        ) as out_file:
            try:
                p = subprocess.Popen(
                    args,
                    stdin=subprocess.PIPE,
                    stdout=out_file,
                    stderr=subprocess.PIPE,
                    env=self._local_env(),
                )
            except OSError:
                raise AnsibleError(
                    "{0} connection requires dd command in the container to fetch files".format(
                        self.transport
                    )
                )
            stdout, stderr = p.communicate()
            self.delete_temporary_file()

            if p.returncode != 0:
                raise AnsibleError(
                    "failed to fetch file %s to %s:\n%s\n%s"
                    % (in_path, out_path, stdout, stderr)
                )

        if actual_out_path != out_path:
            os.rename(
                to_bytes(actual_out_path, errors="strict"),
                to_bytes(out_path, errors="strict"),
            )

    def put_file(self, in_path, out_path):
        ''' transfer a file from local to remote jail '''

        with self.tempfile() as tmp:
            super(Connection, self).put_file(in_path, tmp)
            self._put_file(tmp, out_path)

    def fetch_file(self, in_path, out_path):
        ''' fetch a file from remote to local '''

        with self.tempfile() as tmp:
            self._fetch_file(in_path, tmp)
            super(Connection, self).copy_file(tmp, out_path)

    ### adapted/copied from kubectl.py
    def close(self):
        """Terminate the connection. Nothing to do for kubectl"""
        super(Connection, self).close()
        self._connected = False
