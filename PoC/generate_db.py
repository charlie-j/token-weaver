from os import urandom
from tqdm import tqdm
from ProviderStore import UnlinkableTokens, LinkableTokens, NUM_UNLINKED_BUCKETS, get_unlinked_db_path
import random
import json
import shutil

def main():
    TOTAL_LINKABLE_TOKENS = 10**6
    BUCKET_UNLIBKABLE_TOKENS = (20 * TOTAL_LINKABLE_TOKENS) // NUM_UNLINKED_BUCKETS
    SAVED_LINKABLES = 3000
    
    PROGRESS_STEPS = 20
    assert BUCKET_UNLIBKABLE_TOKENS % PROGRESS_STEPS == 0

    UnlinkableTokens.reset_store()
    unlinkable = UnlinkableTokens()

    print('Generating fake unlinkable tokens db')
    for _ in tqdm(range(PROGRESS_STEPS)):
        values = [b'\x00' + urandom(31) for _ in range(BUCKET_UNLIBKABLE_TOKENS // PROGRESS_STEPS)]
        for val in values:
            unlinkable.add(val, commit=False)
        unlinkable._commit()
    
    for i in range(1, NUM_UNLINKED_BUCKETS):
        shutil.copyfile(get_unlinked_db_path(0), get_unlinked_db_path(i))
    
    print('Unlinkable tokens:', len(unlinkable))

    LinkableTokens.reset_store()
    linkable = LinkableTokens()
    saved_linkables = []

    print('Generating fake linkable tokens db')
    for _ in tqdm(range(PROGRESS_STEPS)):
        values = [(int.from_bytes(urandom(8), 'big') & 0x7fffffffffffffff, urandom(32))
                for _ in range(TOTAL_LINKABLE_TOKENS//PROGRESS_STEPS)]
        saved_linkables.extend(random.sample(values, SAVED_LINKABLES//PROGRESS_STEPS))
        linkable.add_all(values)
    print('Linkable pairs:', len(linkable))

    with open('saved_tokens.json', 'w') as f:
        json.dump([(sn, lt.decode('latin1')) for sn, lt in saved_linkables], f)

if __name__ == '__main__':
    main()