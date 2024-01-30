import sqlite3
from typing import Optional, List, Tuple

DB_PATH = "/tmp/db"
NUM_UNLINKED_BUCKETS = 1

def get_linked_db():
    provider_db = sqlite3.connect(f"{DB_PATH}/linked.db")
    # Enable Memory Mapped IO
    provider_db.execute(f'PRAGMA mmap_size={2*1024*1024*1024}')

    return provider_db

def get_unlinked_db_path(db_id: int):
    return f"{DB_PATH}/unlinked_{db_id}.db"

def get_unlinked_db(db_id: int):
    provider_db = sqlite3.connect(get_unlinked_db_path(db_id))
    # Enable Memory Mapped IO
    provider_db.execute(f'PRAGMA mmap_size={2*1024*1024*1024}')

    return provider_db


class LinkableTokens:
    def reset_store():
        provider_db = get_linked_db()
        provider_db.execute('DROP TABLE IF EXISTS linkable_tokens')
        provider_db.execute('CREATE TABLE linkable_tokens(serial_number int8 not null primary key, token binary(32) not null)')

    def __init__(self):
        self.provider_db = get_linked_db()

    def add(self, sn: int, token: bytes):
        self.add_all([(sn, token)])
    
    def add_all(self, values: List[Tuple[int, bytes]]):
        self.provider_db.executemany('INSERT INTO linkable_tokens VALUES (?, ?)', values)
        self.provider_db.commit()
    
    def remove(self, sn: int):
        # Remove row from table
        self.provider_db.execute('DELETE FROM linkable_tokens WHERE serial_number = ?', (sn,))
        self.provider_db.commit()
    
    def update(self, sn: int, token: bytes):
        # Update table row
        self.provider_db.execute('UPDATE linkable_tokens SET token = ? WHERE serial_number = ?', (token, sn))
        self.provider_db.commit()
    
    def get(self, sn: int) -> Optional[bytes]:
        # Fetch the token of the given serial number from the table
        cursor = self.provider_db.execute('SELECT token FROM linkable_tokens WHERE serial_number=?', (sn,))
        result_tuple = cursor.fetchone()
        if result_tuple is None:
            return None
        else:
            return result_tuple[0]
    
    def __len__(self) -> int:
        cursor = self.provider_db.execute('SELECT count(RowID) FROM linkable_tokens')
        return cursor.fetchone()[0]

class UnlinkableTokens:
    def reset_store():
        for i in range(NUM_UNLINKED_BUCKETS):
            provider_db = get_unlinked_db(i)
            provider_db.execute('DROP TABLE IF EXISTS unlinkable_tokens')
            provider_db.execute('CREATE TABLE unlinkable_tokens(token binary(32) not null primary key)')

    def __init__(self):
        self.provider_dbs = [get_unlinked_db(i) for i in range(NUM_UNLINKED_BUCKETS)]

    def _get_bucket(self, token: bytes) -> int:
        assert NUM_UNLINKED_BUCKETS <= 256
        bucket = token[0] % NUM_UNLINKED_BUCKETS
        return bucket

    def add(self, token: bytes, commit=True):
        bucket = self._get_bucket(token)

        self.provider_dbs[bucket].execute('INSERT INTO unlinkable_tokens VALUES (?)', (token,))
        if commit:
            self.provider_dbs[bucket].commit()
    
    def _commit(self):
        for i in range(NUM_UNLINKED_BUCKETS):
            self.provider_dbs[i].commit()
    
    def __contains__(self, token: bytes) -> bool:
        bucket = self._get_bucket(token)

        # Query database
        res = self.provider_dbs[bucket].execute('SELECT token FROM unlinkable_tokens WHERE token=?', (token,))
        result = res.fetchone() is not None
        
        return result

    def __len__(self) -> int:
        size = 0
        for i in range(NUM_UNLINKED_BUCKETS):
            cursor = self.provider_dbs[i].execute('SELECT count(RowID) FROM unlinkable_tokens')
            size += cursor.fetchone()[0]
        return size