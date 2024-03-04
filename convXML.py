import pandas as pd

dr = {'port': 443, 'proto': 'tcp', 'status': 'open', 'reason':'syn-ack','ttl': 64}

ls =list(dr)
print(ls)
df = pd.DataFrame(ls, columns=['Attribute', 'Value'])
