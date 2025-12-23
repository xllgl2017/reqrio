from setuptools import setup, find_packages

setup(name='reqrio', version='0.0.4', packages=find_packages(),
      package_data={'reqrio': ['*.dll']}, include_package_data=True )

'''
D:\projects\py\baidu\.venv\Scripts\python.exe -m pip install --upgrade twine
D:\projects\py\baidu\.venv\Scripts\python.exe -m build
D:\projects\py\baidu\.venv\Scripts\python.exe -m twine upload .\dist\* --verbose
'''