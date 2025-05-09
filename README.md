# ansible-sshkubectll

An Ansible connection plugin for remotely provisioning kubernetes containers.

This works by SSHing to the host capable of accessing the kubernetes API (typically a cluster member) using the standard **Ansible** SSH _connection_, using it for storing temporary files, and controlling the target container from there via kubectl.

This is a merge of two connection plugins:

* [ansible-sshjail](https://github.com/austinhyde/ansible-sshjail)
* [kubectl](https://github.com/ansible-collections/kubernetes.core/blob/main/plugins/connection/kubectl.py) from [kubernetes-core](https://github.com/ansible-collections/kubernetes.core)

# Requirements

Control node (your workstation or deployment server):

* Ansible 2.16+
* Python 3

kubectl host:

* accessible by SSH
* kubectl binary installed
* Python 3

Target container:

* Python 3

# Installation

This is a "Connection Type Plugin", as outlined in the [Ansible docs](http://docs.ansible.com/developing_plugins.html#connection-type-plugins).

To install sshjail:

1. Clone this repo.
2. Copy or link `sshkubectl.py` to one of the supported locations:
  * `/usr/share/ansible/plugins/connection_plugins/sshkubectl.py`
  * `path/to/your/toplevelplaybook/connection_plugins/sshkubectl.py`

# Usage

TBD

# Known Issues

See [the issue tracker](https://github.com/aardsoft/ansible-sshkubectl/issues)

# Contributing

Let me know if you have any difficulties using this, by creating an issue.

Pull requests are always welcome! I'll try to get them reviewed in a timely manner.
