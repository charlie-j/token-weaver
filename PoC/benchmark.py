import json
from TokenWeaver_database import Provider, TEE
from timeit import default_timer as timer
from tqdm import tqdm

def linkables_benchmark(provider: Provider, linkables):
	linkable_time = 0
	linkable_tee_time = 0
	linkable_provider_time = 0
	linkable_provider_db_time = 0
	linkable_provider_crypt_time = 0
	for sn, lt in tqdm(linkables):
		# Setup
		tee = TEE(provider.pkP, provider.pkA, sn, lt)

		# Linkable Operation
		t1 = timer()
		imsg1 = tee.unlinkable_chain_init()
		t2 = timer()
		imsg2, db_t, crypt_t = provider.unlinkable_chain_request(imsg1)
		t3 = timer()
		tee.unlinkable_chain_finalize(imsg2)
		t4 = timer()
		
		linkable_time += t4 - t1
		linkable_tee_time += (t2 - t1) + (t4 - t3)
		linkable_provider_time += t3 - t2
		linkable_provider_db_time += db_t
		linkable_provider_crypt_time += crypt_t
	
	linkable_time /= len(linkables)
	linkable_tee_time /= len(linkables)
	linkable_provider_time /= len(linkables)
	linkable_provider_db_time /= len(linkables)
	linkable_provider_crypt_time /= len(linkables)
	print(f'Average linkable operation time: {linkable_time:.3f}s, \
TEE time: {linkable_tee_time:.3f}s, \
Provider time: {linkable_provider_time:.3f}s \
Provider DB time: {linkable_provider_db_time:.3f}s \
Provider Crypto time: {linkable_provider_crypt_time:.3f}s \
[{len(linkables)} iterations]')

def unlinkables_benchmark(provider: Provider, linkables):
	unlinkable_time = 0
	unlinkable_tee_time = 0
	unlinkable_provider_time = 0
	unlinkable_provider_db_time = 0
	unlinkable_provider_crypt_time = 0
	for sn, lt in tqdm(linkables):
		# Setup, initialize unlinkable chain
		tee = TEE(provider.pkP, provider.pkA, sn, lt)
		imsg1 = tee.unlinkable_chain_init()
		imsg2, _, _ = provider.unlinkable_chain_request(imsg1)
		tee.unlinkable_chain_finalize(imsg2)

		# Unlinkable Operation
		t1 = timer()
		ACmsg1 = tee.ac_provisioning_init()
		t2 = timer()
		ACmsg2, db_t, crypt_t = provider.ac_provisioning_request(ACmsg1)
		t3 = timer()
		tee.ac_provisioning_finalize(ACmsg2)
		t4 = timer()

		unlinkable_time += t4 - t1
		unlinkable_tee_time += (t2 - t1) + (t4 - t3)
		unlinkable_provider_time += t3 - t2
		unlinkable_provider_db_time += db_t
		unlinkable_provider_crypt_time += crypt_t
	
	unlinkable_time /= len(linkables)
	unlinkable_tee_time /= len(linkables)
	unlinkable_provider_time /= len(linkables)
	unlinkable_provider_db_time /= len(linkables)
	unlinkable_provider_crypt_time /= len(linkables)
	print(f'Average unlinkable operation time: {unlinkable_time:.3f}s, \
TEE time: {unlinkable_tee_time:.3f}s, \
Provider time: {unlinkable_provider_time:.3f}s \
Provider DB time: {unlinkable_provider_db_time:.3f}s \
Provider Crypto time: {unlinkable_provider_crypt_time:.3f}s \
[{len(linkables)} iterations]')

def main():
	with open('saved_tokens.json', 'r') as f:
		saved_tokens = json.load(f)

	saved_linkables = [(sn, lt.encode('latin1')) for sn, lt in saved_tokens]

	provider = Provider()
	num_linked = len(provider.linkable_tokens)
	num_unlinked = len(provider.unlinkable_tokens)
	print(f'Running benchmark on DB with {num_linked} linkable pairs and {num_unlinked} unlinkable token')

	NUM_LINKED_ITERS = 1000
	linkables_benchmark(provider, saved_linkables[:NUM_LINKED_ITERS])

	NUM_UNLINKED_ITERS = 1000
	unlinkables_benchmark(provider, saved_linkables[NUM_LINKED_ITERS:][:NUM_UNLINKED_ITERS])


if __name__ == '__main__':
	main()