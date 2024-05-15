pushd ms-matrix
git clone https://github.com/microsoft/Threat-Matrix-for-Kubernetes.git
popd

CALL pipenv install
mkdir build
CALL pipenv run python ./src/parse.py
