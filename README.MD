# API Wrapper

This API is a wrapper for OpenAI's API.  Its purpose is to allow organizations to administer use of a 
single API key.  So the organization purchases a single key from the vendor and gives access to users within the 
org.  This eliminates the need for every user to get their own API key from the vendor.  

Usage can be tracked and costs per user can be calculated.  For organizations with many departments, this wrapper 
helps track monthly costs by department. 

To run the service locally, either use Docker or run:
```commandline
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
