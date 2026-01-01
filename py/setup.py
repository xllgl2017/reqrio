from setuptools import setup, find_packages

setup(name='reqrio', version='0.0.8', packages=find_packages(),
      package_data={'reqrio': ['*.dll']}, include_package_data=True, entry_points={
        'pyinstaller40': ["hook-dirs=reqrio.hooks"]
    })

'''
D:\projects\py\baidu\.venv\Scripts\python.exe -m pip install --upgrade twine
D:\projects\py\baidu\.venv\Scripts\python.exe -m build
D:\projects\py\baidu\.venv\Scripts\python.exe -m twine upload .\dist\* --verbose
'''
