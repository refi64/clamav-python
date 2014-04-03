requirements = ['cffi']

try:
    from setuptools import setup
except:
    from distutils.core import setup
    kw = {}
else:
    kw = {'install_requires': requirements}

import clamav

try:
    with open('README.rst', 'r') as f:
        readme = f.read()
except:
    readme = ''

setup(name='clamav',
      version=str(clamav.__version__),
      author='Ryan Gonzalez',
      author_email='kirbyfan64sos@gmail.com',
      py_modules=['clamav'],
      description='A Python interface to ClamAV.',
      long_description=readme,
      requires=requirements,
      classifiers=[
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2',
          'Programming Language :: Python :: 3'],
      **kw
      )

