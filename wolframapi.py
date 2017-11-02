import wolframalpha

app_id="LH259U-2X7QT3WQP4"

client = wolframalpha.Client(app_id)

query = input("Query: ")

res = client.query(query)

for pod in res.pods:
    for subpod in pod.subpods:
        print(subpod.plaintext)
