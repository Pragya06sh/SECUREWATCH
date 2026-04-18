import hashlib
import json
import time


class Block:

    def __init__(self, index, timestamp, data, previous_hash):

        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):

        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash
        }, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()


class Blockchain:

    def __init__(self):

        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):

        return Block(
            0,
            time.time(),
            {"message": "Genesis Block"},
            "0"
        )

    def get_latest_block(self):

        return self.chain[-1]

    def add_block(self, data):

        previous_block = self.get_latest_block()

        new_block = Block(
            len(self.chain),
            time.time(),
            data,
            previous_block.hash
        )

        self.chain.append(new_block)

        print("\n🔗 Block Added To Blockchain")
        print("Index:", new_block.index)
        print("Hash:", new_block.hash)

    # ----------------------------------

    def save_chain(self):

        chain_data = []

        for block in self.chain:

            chain_data.append({
                "index": block.index,
                "timestamp": block.timestamp,
                "data": block.data,
                "previous_hash": block.previous_hash,
                "hash": block.hash
            })

        with open("blockchain_logs.json", "w") as f:
            json.dump(chain_data, f, indent=4)

        print("\n📁 Blockchain saved to blockchain_logs.json")

    # ----------------------------------

    def display_chain(self):

        print("\n========== BLOCKCHAIN ==========\n")

        for block in self.chain:

            print("Block:", block.index)
            print("Data:", block.data)
            print("Hash:", block.hash)
            print("-" * 40)

    # ----------------------------------

    def is_chain_valid(self):

        for i in range(1, len(self.chain)):

            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                return False

            if current.previous_hash != previous.hash:
                return False

        return True