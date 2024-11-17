from flask import Flask, jsonify, request
from neo4j import GraphDatabase, basic_auth
from flask_cors import CORS, cross_origin

# Initialize Flask app
app = Flask(__name__)
#CORS(app)  # This will enable CORS for all routes
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
# Neo4j connection details
NEO4J_URI = "bolt://DESKTOP-F191J35.local:7687"  # Replace with your Neo4j URI
NEO4J_USER = "neo4j"  # Replace with your username
NEO4J_PASSWORD = "password"  # Replace with your password

# Initialize Neo4j driver
driver = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))

# Route: Home
@app.route('/')
def home():
    return "Cybersecurity Risk Management API is running!"

# Route: Get all assets
@app.route('/assets', methods=['GET'])
@cross_origin()
def get_assets():
    with driver.session() as session:
        query = "MATCH (a:Asset) RETURN a"
        result = session.run(query)
        # Extract properties of each node
        assets = [record["a"]._properties for record in result]
    return jsonify(assets)



# # Route: Get all threats
# @app.route('/threats', methods=['GET'])
# def get_threats():
#     with driver.session() as session:
#         query = "MATCH (t:Threat) RETURN t.name AS name, t.severityLevel AS severity, t.description AS description"
#         result = session.run(query)
#         threats = [{"name": record["name"], "severity": record["severity"], "description": record["description"]} for record in result]
#     return jsonify(threats)

@app.route('/assets', methods=['POST'])
def create_asset():
    data = request.json  # JSON payload from the client
    with driver.session() as session:
        query = """
        CREATE (a:Asset {
            assetID: $assetID,
            assetName: $assetName,
            assetType: $assetType,
            criticality: $criticality,
            owner: $owner,
            location: $location,
            dataSensitivity: $dataSensitivity,
            softwareVersion: $softwareVersion,
            configuration: $configuration,
            riskScore: $riskScore,
            lastUpdated: $lastUpdated
        }) RETURN a
        """
        result = session.run(query, **data)
        new_asset = result.single()["a"]._properties
    return jsonify(new_asset), 201

@app.route('/assets/<assetID>', methods=['PUT'])
def update_asset(assetID):
    data = request.json  # JSON payload for the update
    with driver.session() as session:
        query = """
        MATCH (a:Asset {assetID: $assetID})
        SET a += $data
        RETURN a
        """
        result = session.run(query, assetID=assetID, data=data)
        updated_asset = result.single()["a"]._properties
    return jsonify(updated_asset)

@app.route('/assets/<assetID>', methods=['DELETE'])
def delete_asset(assetID):
    with driver.session() as session:
        query = """
        MATCH (a:Asset {assetID: $assetID})
        DELETE a
        RETURN COUNT(a) AS deletedCount
        """
        result = session.run(query, assetID=assetID)
        deleted_count = result.single()["deletedCount"]
    if deleted_count > 0:
        return jsonify({"message": "Asset deleted successfully"}), 200
    else:
        return jsonify({"error": "Asset not found"}), 404


# Route: Get all threats
@app.route('/threats', methods=['GET'])
def get_threats():
    with driver.session() as session:
        query = "MATCH (t:Threat) RETURN t"
        result = session.run(query)
        threats = [record["t"] for record in result]
    return jsonify([threat._properties for threat in threats])

# Route: Create a new threat
@app.route('/threats', methods=['POST'])
def create_threat():
    data = request.json
    with driver.session() as session:
        query = """
        CREATE (t:Threat {
            id: $id,
            name: $name,
            description: $description,
            severityLevel: $severityLevel,
            affectedAssets: $affectedAssets,
            likelihood: $likelihood,
            dateIdentified: $dateIdentified,
            attackVector: $attackVector,
            type: $type,
            severityScore: $severityScore,
            status: $status
        })
        RETURN t
        """
        result = session.run(query, **data)
        created_threat = result.single()["t"]
    return jsonify(created_threat._properties), 201

# Route: Update an existing threat
@app.route('/threats/<threat_id>', methods=['PUT'])
def update_threat(threat_id):
    data = request.json
    with driver.session() as session:
        query = """
        MATCH (t:Threat {id: $id})
        SET t += $updates
        RETURN t
        """
        result = session.run(query, id=threat_id, updates=data)
        updated_threat = result.single()
        if updated_threat:
            return jsonify(updated_threat["t"]._properties)
        else:
            return jsonify({"error": "Threat not found"}), 404

# Route: Delete a threat
@app.route('/threats/<threat_id>', methods=['DELETE'])
def delete_threat(threat_id):
    with driver.session() as session:
        query = """
        MATCH (t:Threat {id: $id})
        DELETE t
        RETURN COUNT(t) AS count
        """
        result = session.run(query, id=threat_id)
        count = result.single()["count"]
        if count > 0:
            return jsonify({"message": "Threat deleted successfully"})
        else:
            return jsonify({"error": "Threat not found"}), 404

# Route: Get all vulnerabilities
@app.route('/vulnerabilities', methods=['GET'])
@cross_origin()
def get_vulnerabilities():
    with driver.session() as session:
        query = "MATCH (v:Vulnerability) RETURN v"
        result = session.run(query)
        vulnerabilities = [record["v"] for record in result]
    return jsonify([vuln._properties for vuln in vulnerabilities])

# Route: Create a new vulnerability
@app.route('/vulnerabilities', methods=['POST'])
def create_vulnerability():
    data = request.json
    with driver.session() as session:
        query = """
        CREATE (v:Vulnerability {
            vulnID: $vulnID,
            vulnName: $vulnName,
            severity: $severity
        })
        RETURN v
        """
        result = session.run(query, **data)
        created_vuln = result.single()["v"]
    return jsonify(created_vuln._properties), 201

# Route: Update an existing vulnerability
@app.route('/vulnerabilities/<vuln_id>', methods=['PUT'])
def update_vulnerability(vuln_id):
    data = request.json
    with driver.session() as session:
        query = """
        MATCH (v:Vulnerability {vulnID: $vulnID})
        SET v += $updates
        RETURN v
        """
        result = session.run(query, vulnID=vuln_id, updates=data)
        updated_vuln = result.single()
        if updated_vuln:
            return jsonify(updated_vuln["v"]._properties)
        else:
            return jsonify({"error": "Vulnerability not found"}), 404

# Route: Delete a vulnerability
@app.route('/vulnerabilities/<vuln_id>', methods=['DELETE'])
def delete_vulnerability(vuln_id):
    with driver.session() as session:
        query = """
        MATCH (v:Vulnerability {vulnID: $vulnID})
        DELETE v
        RETURN COUNT(v) AS count
        """
        result = session.run(query, vulnID=vuln_id)
        count = result.single()["count"]
        if count > 0:
            return jsonify({"message": "Vulnerability deleted successfully"})
        else:
            return jsonify({"error": "Vulnerability not found"}), 404


# Route: Get all controls
@app.route('/controls', methods=['GET'])
def get_controls():
    with driver.session() as session:
        query = "MATCH (c:Control) RETURN c"
        result = session.run(query)
        controls = [record["c"] for record in result]
    return jsonify([control._properties for control in controls])

# Route: Create a new control
@app.route('/controls', methods=['POST'])
def create_control():
    data = request.json
    with driver.session() as session:
        query = """
        CREATE (c:Control {
            controlID: $controlID,
            controlName: $controlName,
            effectiveness: $effectiveness
        })
        RETURN c
        """
        result = session.run(query, **data)
        created_control = result.single()["c"]
    return jsonify(created_control._properties), 201

# Route: Update an existing control
@app.route('/controls/<control_id>', methods=['PUT'])
def update_control(control_id):
    data = request.json
    with driver.session() as session:
        query = """
        MATCH (c:Control {controlID: $controlID})
        SET c += $updates
        RETURN c
        """
        result = session.run(query, controlID=control_id, updates=data)
        updated_control = result.single()
        if updated_control:
            return jsonify(updated_control["c"]._properties)
        else:
            return jsonify({"error": "Control not found"}), 404

# Route: Delete a control
@app.route('/controls/<control_id>', methods=['DELETE'])
def delete_control(control_id):
    with driver.session() as session:
        query = """
        MATCH (c:Control {controlID: $controlID})
        DELETE c
        RETURN COUNT(c) AS count
        """
        result = session.run(query, controlID=control_id)
        count = result.single()["count"]
        if count > 0:
            return jsonify({"message": "Control deleted successfully"})
        else:
            return jsonify({"error": "Control not found"}), 404

# Route: Get all incidents
@app.route('/incidents', methods=['GET'])
def get_incidents():
    with driver.session() as session:
        query = "MATCH (i:Incident) RETURN i"
        result = session.run(query)
        incidents = [record["i"] for record in result]
    return jsonify([incident._properties for incident in incidents])

# Route: Create a new incident
@app.route('/incidents', methods=['POST'])
def create_incident():
    data = request.json
    with driver.session() as session:
        query = """
        CREATE (i:Incident {
            incidentID: $incidentID,
            incidentName: $incidentName,
            date: $date,
            impact: $impact
        })
        RETURN i
        """
        result = session.run(query, **data)
        created_incident = result.single()["i"]
    return jsonify(created_incident._properties), 201

# Route: Update an existing incident
@app.route('/incidents/<incident_id>', methods=['PUT'])
def update_incident(incident_id):
    data = request.json
    with driver.session() as session:
        query = """
        MATCH (i:Incident {incidentID: $incidentID})
        SET i += $updates
        RETURN i
        """
        result = session.run(query, incidentID=incident_id, updates=data)
        updated_incident = result.single()
        if updated_incident:
            return jsonify(updated_incident["i"]._properties)
        else:
            return jsonify({"error": "Incident not found"}), 404

# Route: Delete an incident
@app.route('/incidents/<incident_id>', methods=['DELETE'])
def delete_incident(incident_id):
    with driver.session() as session:
        query = """
        MATCH (i:Incident {incidentID: $incidentID})
        DELETE i
        RETURN COUNT(i) AS count
        """
        result = session.run(query, incidentID=incident_id)
        count = result.single()["count"]
        if count > 0:
            return jsonify({"message": "Incident deleted successfully"})
        else:
            return jsonify({"error": "Incident not found"}), 404

# Route: Link an asset to a threat
@app.route('/link_asset_threat', methods=['POST'])
def link_asset_threat():
    data = request.json
    asset_name = data.get("asset_name")
    threat_name = data.get("threat_name")
    
    if not asset_name or not threat_name:
        return jsonify({"error": "Asset name and Threat name are required"}), 400
    
    with driver.session() as session:
        query = """
        MATCH (a:Asset {name: $asset_name}), (t:Threat {name: $threat_name})
        MERGE (a)-[:EXPOSED_TO]->(t)
        RETURN a.name AS asset, t.name AS threat
        """
        result = session.run(query, asset_name=asset_name, threat_name=threat_name)
        links = [{"asset": record["asset"], "threat": record["threat"]} for record in result]
    
    if links:
        return jsonify({"message": "Link created", "links": links})
    else:
        return jsonify({"error": "Asset or Threat not found"}), 404

# Route: Get all relationships
@app.route('/relationships', methods=['GET'])
def get_relationships():
    with driver.session() as session:
        query = """
        MATCH (a:Asset)-[r:EXPOSED_TO]->(t:Threat)
        RETURN a.name AS asset, t.name AS threat, r AS relationship
        """
        result = session.run(query)
        relationships = [{"asset": record["asset"], "threat": record["threat"]} for record in result]
    return jsonify(relationships)

# Route: Calculate risk scores (example endpoint)
@app.route('/calculate_risk', methods=['GET'])
def calculate_risk():
    with driver.session() as session:
        query = """
        MATCH (a:Asset)-[:EXPOSED_TO]->(t:Threat)
        RETURN a.name AS asset, t.name AS threat, t.severityLevel AS severity
        """
        result = session.run(query)
        risks = [
            {
                "asset": record["asset"],
                "threat": record["threat"],
                "risk_score": int(record["severity"]) * 10  # Example risk calculation
            }
            for record in result
        ]
    return jsonify(risks)


# @app.route('/graph', methods=['GET'])
# def get_graph():
#     with driver.session() as session:
#         # Query to get nodes and relationships (edges)
#         query = """
#         MATCH (n)-[r]->(m)
#         RETURN n, m, type(r) as relationship
#         """
#         result = session.run(query)
        
#         nodes = {}
#         links = []

#         for record in result:
#             # Add nodes to the dictionary
#             n = record["n"]
#             m = record["m"]
#             nodes[n.id] = n
#             nodes[m.id] = m

#             # Add link (edge) between nodes
#             links.append({
#                 "source": n.id,
#                 "target": m.id,
#                 "label": record["relationship"]
#             })

#         # Return the graph structure as JSON
#         return jsonify({
#             "nodes": [node for node in nodes.values()],
#             "links": links
#         })

@app.route('/graph', methods=['GET'])
@cross_origin()
def get_graph():
    with driver.session() as session:
        # Query to get nodes and relationships (edges)
        query = """
        MATCH (n)-[r]->(m)
        RETURN n, m, type(r) as relationship
        """
        result = session.run(query)
        
        nodes = {}
        links = []

        for record in result:
            # Convert Neo4j Node to a dictionary
            n = record["n"]
            m = record["m"]
            n_dict = {
                "id": n.id,
                "labels": list(n.labels),  # Convert frozenset to list
                "properties": dict(n)  # Convert properties to a dictionary
            }
            m_dict = {
                "id": m.id,
                "labels": list(m.labels),  # Convert frozenset to list
                "properties": dict(m)  # Convert properties to a dictionary
            }

            # Add nodes to the dictionary
            nodes[n.id] = n_dict
            nodes[m.id] = m_dict

            # Add link (edge) between nodes
            links.append({
                "source": n.id,
                "target": m.id,
                "label": record["relationship"]
            })

        # Return the graph structure as JSON
        return jsonify({
            "nodes": list(nodes.values()),
            "links": links
        })
    
@app.route('/link_asset_vulnerability', methods=['POST'])
@cross_origin()
def link_asset_vulnerability():
    data = request.json  # Get the JSON payload from the client
    asset_name = data.get('assetName')  # Adjusted for your schema
    vulnerability_name = data.get('vulnName')  # Adjusted for your schema

    if not asset_name or not vulnerability_name:
        return jsonify({"error": "Both assetName and vulnName are required."}), 400

    with driver.session() as session:
        # First, check if the asset and vulnerability exist
        asset_query = "MATCH (a:Asset {assetName: $asset_name}) RETURN a"
        vulnerability_query = "MATCH (v:Vulnerability {vulnName: $vulnerability_name}) RETURN v"

        asset_result = session.run(asset_query, asset_name=asset_name)
        vulnerability_result = session.run(vulnerability_query, vulnerability_name=vulnerability_name)

        asset = asset_result.single()
        vulnerability = vulnerability_result.single()

        if not asset:
            return jsonify({"error": "Asset not found."}), 404
        if not vulnerability:
            return jsonify({"error": "Vulnerability not found."}), 404

        # Use MERGE to create the relationship between asset and vulnerability
        link_query = """
        MATCH (a:Asset {assetName: $asset_name}), (v:Vulnerability {vulnName: $vulnerability_name})
        MERGE (a)-[:LINKED_TO]->(v)
        RETURN a, v
        """
        session.run(link_query, asset_name=asset_name, vulnerability_name=vulnerability_name)

    return jsonify({"message": f"Successfully linked {asset_name} to {vulnerability_name}."}), 201

# Teardown: Close Neo4j driver when the app shuts down
@app.teardown_appcontext
def close_driver(exception):
    if driver:
        driver.close()

# Run the Flask app
if __name__ == "__main__":
    #app.run(debug=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
