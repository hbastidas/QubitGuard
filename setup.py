from setuptools import setup, find_packages

setup(
    name='QubitGuard',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'cryptography>=41.0.0',
        'liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python.git',
        'click>=8.0.0',
    ],
    entry_points={
        'console_scripts': [
            'qubitguard=QubitGuard.cli:cli',
        ],
    },
    author='Heber Bastidas',
    author_email='heberbastidas@gmail.com',
    description='Post-quantum cryptographic suite for quantum-resistant security',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/hbastidas/QubitGuard',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.8',
)
