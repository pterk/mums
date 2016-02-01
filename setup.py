from setuptools import setup

setup(
    name='mums',
    license='BSD',
    url='http://github.com/pterk/mums',
    version='0.4.1',
    py_modules=['mums'],
    install_requires=[
        'pycrypto',
    ],
    entry_points='''
        [console_scripts]
        mums=mums:mums
    ''',
    author='Peter van Kampen',
    author_email='pterk@datatailors.com',
    description="Simple encrypted environment variables",
    classifiers=[
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Operating System :: POSIX',
    ],
)
