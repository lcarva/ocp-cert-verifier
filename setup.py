from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='ocp-cert-verifier',
    version='0.1.0',
    description='Verify expiration of certificates in Secret objects in an OCP project',
    long_description=readme,
    author='Luiz Carvalho',
    author_email='lui@redhat.com',
    url='https://github.com/lcarva/ocp-cert-verifier',
    license=license,
    packages=find_packages(exclude=('tests',)),
    entry_points={
        'console_scripts': [
            'ocp-cert-verify = ocp_cert_verifier.__main__:main',
        ]
    }
)
