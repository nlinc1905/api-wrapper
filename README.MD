# API Wrapper

This API is a wrapper for OpenAI's API.  Its purpose is to allow organizations to administer use of a 
single API key.  So the organization purchases a single key from the vendor and gives access to users within the 
org.  This eliminates the need for every user to get their own API key from the vendor.  

Usage can be tracked and costs per user can be calculated.  For organizations with many departments, this wrapper 
helps track monthly costs by department. 

To run the service locally:
```commandline
# with Docker
docker build -t api-wrapper .
docker run -p 8080:8080 api-wrapper

# without Docker
python -m pip install -r requirements.txt
uvicorn src.main:app
```

## Using Postgres

This API uses Postgres to store user data in dev and prod environments.  See the K8s manifests for details.

## Using SQLite

This API uses SQLite to store user data in a test (local) environment.  To access the DB from the command line, it needs to be installed:

```commandline
sudo apt install sqlite3
```

Once installed, a DB connection can be established from the terminal:

```commandline
sqlite3 openai_wrapper_app.db
```

Commands can now be run from the terminal to explore the DB:

```commandline
.tables
.schema
select name, sql from sqlite_master where type='table';
.exit
```

## Tests

Unit tests can be run using Pytest.  They must be run 1 file at a time to avoid SQLite throwing an error about writing 
to a read-only DB.

```commandline
pytest test/test_crud.py
pytest test/test_main.py
pytest test/test_security.py
```

## Building and Deploying to Kubernetes

Build and tag the image locally, and then run it to make sure all is well.

Assuming you have a remote repository, push it there.  Modify the commands for your region and repository.

```commandline
gcloud auth login
gcloud auth configure-docker us-central1-docker.pkg.dev
docker build -t api-wrapper .
docker tag api-wrapper us-central1-docker.pkg.dev/queryable-docs-dev/queryable-docs-docker-repository/api-wrapper
docker push us-central1-docker.pkg.dev/queryable-docs-dev/queryable-docs-docker-repository/api-wrapper
```

### Test K8s Deployment Locally

Install [Minikube](https://minikube.sigs.k8s.io/docs/start/) and [kubeval](https://kubeval.instrumenta.dev/installation/) (optional).

Start Minikube. The first time it starts, it will download Kubernetes, so give it a minute.

```
minikube start
```

Make sure you see the add-ons ingress and ingress-dns enabled. If they are not enabled automatically, you can do it:

```
minikube addons enable ingress
minikube addons enable ingress-dns
```

Make sure the image pull policy in `k8s/wrapper-deployment.yaml` is set to never: `imagePullPolicy: Never`. 

`cd` into the `k8s/` folder and apply the manifests:

```
kubectl apply -f .
```

Check to see everything is running:

```
kubectl get pods -n semantic-search
kubectl get ingress -n semantic-search
```

Go to the HTTP and port specified in the ingress, e.g. http://192.168.49.2:80

To delete everything:

```commandline
kubectl delete namespaces semantic-search
kubectl get pv
kubectl delete pv <pv>
```
