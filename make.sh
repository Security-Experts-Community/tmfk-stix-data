pushd ms-matrix
git clone https://github.com/microsoft/Threat-Matrix-for-Kubernetes.git
popd

pipenv install
mkdir build
pipenv run python ./src/parse.py