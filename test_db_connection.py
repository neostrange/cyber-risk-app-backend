from neo4j import GraphDatabase, basic_auth

# Define the connection details
uri = "bolt://DESKTOP-F191J35.local:7687"  # Replace with your Neo4j server URI if different
username = "neo4j"
password = "password"

# Create the Neo4j driver instance
driver = GraphDatabase.driver(uri, auth=basic_auth(username, password))

# Define a function to perform a simple query
def test_connection():
    with driver.session() as session:
        result = session.run("RETURN 'Connection successful!' AS message")
        for record in result:
            print(record["message"])

# Call the function
try:
    test_connection()
finally:
    driver.close()
