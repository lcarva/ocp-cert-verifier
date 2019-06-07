# ocp-cert-verifier

Verify expiration of certificates in Secret objects in an OCP project

## Installation

### pip

```python
pip install -r requirements.txt .
```

### Container Image

A container image is available from `quay.io/factory2/ocp-cert-verifier`.

## Usage

After installation, the executable `ocp-cert-verifier` should be available for execution.
Use the `--help` parameter for a list of options.

Example:

```bash
🐚  ocp-cert-verify myproject
WARNING: myproject:auth:cert1 expires in 2 days on: 2019-06-09 19:29:46
OK: myproject:auth:cert2 expires in 159 days on: 2019-11-13 09:21:31
```
