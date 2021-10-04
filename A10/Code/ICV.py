import hashlib
import hmac

print("List of Available Algorithms to Construct Secure Hash/Message Digest : {}".format(hashlib.algorithms_available))
print("\nList of Algorithms Guaranteed to Work : {}".format(hashlib.algorithms_guaranteed))
print("\nList of Algorithms that May Work : {}".format(hashlib.algorithms_available.difference(hashlib.algorithms_guaranteed)))


################################################################################################################################


message = "Message to authenticate"
key= "v30nE9iDBSlWlIzViAiqmgvIypz0v4qjGmiYHbNoXn8="

########## 1 ##################
hmac1 = hmac.new(key=key.encode(), msg=message.encode(), digestmod="sha1")
message_digest1 = hmac1.digest()

print("{} - Message Digest 1 : {}".format(hmac1.name, message_digest1))

########## 2 ##################
hmac2 = hmac.new(key=key.encode(), digestmod="sha1")
hmac2.update(bytes(message, encoding="utf-8"))
message_digest2 = hmac2.digest()

print("{} - Message Digest 2 : {}".format(hmac2.name, message_digest2))

########## 3 ##################
hmac3 = hmac.new(key=key.encode(), digestmod="sha1")
hmac3.update(bytes("Welcome to ", encoding="utf-8"))
hmac3.update(bytes("CoderzColumn.", encoding="utf-8"))
message_digest3 = hmac3.digest()

print("{} - Message Digest 3 : {}".format(hmac3.name, message_digest3))


print("\nMessage Digest Size for 1 : {}, 2 : {} and 3 : {}".format(hmac1.digest_size, hmac2.digest_size,hmac3.digest_size,))
print("Message Block  Size for 1 : {}, 2 : {} and 3 : {}".format(hmac1.block_size, hmac2.block_size,hmac3.block_size,))


################################################################################################################################


########## 1 ##################
hmac1 = hmac.new(key=key.encode(), msg=message.encode(), digestmod=hashlib.sha256)
message_digest1 = hmac1.digest()

print("{} - Message Digest 1 : {}".format(hmac1.name, message_digest1))

########## 2 ##################
hmac2 = hmac.new(key=key.encode(), digestmod=hashlib.sha256)
hmac2.update(bytes(message, encoding="utf-8"))
message_digest2 = hmac2.digest()

print("{} - Message Digest 2 : {}".format(hmac2.name, message_digest2))

########## 3 ##################
hmac3 = hmac.new(key=key.encode(), digestmod=hashlib.sha256)
hmac3.update(bytes("Welcome to ", encoding="utf-8"))
hmac3.update(bytes("CoderzColumn.", encoding="utf-8"))
message_digest3 = hmac3.digest()

print("{} - Message Digest 3 : {}".format(hmac3.name, message_digest3))


print("\nMessage Digest Size for 1 : {}, 2 : {} and 3 : {}".format(hmac1.digest_size, hmac2.digest_size,hmac3.digest_size,))
print("Message Block  Size for 1 : {}, 2 : {} and 3 : {}".format(hmac1.block_size, hmac2.block_size,hmac3.block_size,))


################################################################################################################################


########## 1 ##################
hmac1 = hmac.new(key=key.encode(), msg=message.encode(), digestmod=hashlib.sha256)
message_digest1 = hmac1.hexdigest()

print("{} - Hex Message Digest 1 : {}".format(hmac1.name, message_digest1))

########## 2 ##################
hmac2 = hmac.new(key=key.encode(), digestmod=hashlib.sha256)
hmac2.update(bytes(message, encoding="utf-8"))
message_digest2 = hmac2.hexdigest()

print("{} - Hex Message Digest 2 : {}".format(hmac2.name, message_digest2))

########## 3 ##################
hmac3 = hmac.new(key=key.encode(), digestmod=hashlib.sha256)
hmac3.update(bytes("Welcome to ", encoding="utf-8"))
hmac3.update(bytes("CoderzColumn.", encoding="utf-8"))
message_digest3 = hmac3.hexdigest()

print("{} - Hex Message Digest 3 : {}".format(hmac3.name, message_digest3))


print("\nMessage Digest Size for 1 : {}, 2 : {} and 3 : {}".format(hmac1.digest_size, hmac2.digest_size,hmac3.digest_size,))
print("Message Block  Size for 1 : {}, 2 : {} and 3 : {}".format(hmac1.block_size, hmac2.block_size,hmac3.block_size,))


################################################################################################################################


########## 1 ##################
message_digest1 = hmac.digest(key=key.encode(), msg=message.encode(), digest="sha3_256")

print("Message Digest 1 : {}".format(message_digest1))

########## 2 ##################
message_digest2 = hmac.digest(key=key.encode(), msg=bytes(message, encoding="utf-8"), digest=hashlib.sha3_256)

print("Message Digest 2 : {}".format(message_digest2))


################################################################################################################################


########## 1 ##################
message_digest1 = hmac.digest(key=key.encode(), msg=message.encode(), digest="sha3_256")

print("Message Digest 1 : {}".format(message_digest1))

########## 2 ##################
message_digest2 = hmac.digest(key=key.encode(), msg=bytes(message, encoding="utf-8"), digest=hashlib.sha3_256)

print("Message Digest 2 : {}".format(message_digest2))

print("\nIs message digest 1 is equal to message digest 2? : {}".format(hmac.compare_digest(message_digest1, message_digest2)))


################################################################################################################################