"""
Utility for:
1. Encrypting files and storing them in a cloud storage bucket
2. Retrieving encrypted files from a cloud storage bucket and decrypting them

Uses service-account credentials from a JSON file specified by the `GOOGLE_APPLICATION_CREDENTIALS`
environment variable. For more information on this authentication method, see:
https://cloud.google.com/docs/authentication/getting-started
"""

import argparse
import base64
import logging
import os
import tempfile

import googleapiclient.discovery


def store(bucket, key_spec, infile, outfile):
    """
    Encrypts an input file using a given KMS key specification and stores the result under the given
    output path relative to a GCS bucket.

    Args:
        1. bucket - GCS bucket in which the encrypted file should be stored
        2. key_spec - Tuple of the form (project, location, keyring, key, version) which specifies
        the key that should be used to encrypt the input file
        3. infile - Local path to file that should be encrypted and store on GCS
        4. outfile - Path relative to the bucket at which the encrypted file should be stored

    Returns:
        None. Throws an error if something went wrong.
    """
    kms_project, kms_location, kms_keyring, kms_key, kms_key_version = key_spec

    storage_client = googleapiclient.discovery.build('storage', 'v1')

    kms_client = googleapiclient.discovery.build('cloudkms', 'v1')
    kms_encrypt = kms_client.projects().locations().keyRings().cryptoKeys().encrypt

    route = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(*key_spec[:-1])
    if key_spec[-1] is not None:
        route = '{}/cryptoKeyVersions/{}'.format(route, key_spec[-1])

    # KMS REST API requires input to be provided in bas64 encoding
    with open(infile, 'rb') as ifp:
        input_contents = ifp.read()
        input_b64 = base64.b64encode(input_contents).decode()

    kms_response = kms_encrypt(name=route, body={'plaintext': input_b64}).execute()
    ciphertext_b64 = kms_response['ciphertext']
    ciphertext = base64.b64decode(ciphertext_b64)

    _, cipherfile = tempfile.mkstemp()
    with open(cipherfile, 'wb') as cf:
        cf.write(ciphertext)

    storage_client.objects().insert(
        bucket=bucket,
        name=outfile,
        body={
            'metadata': {
                'kms-project': kms_project,
                'kms-location': kms_location,
                'kms-keyring': kms_keyring,
                'kms-key': kms_key,
                'kms-key-version': str(kms_key_version)
            }
        },
        media_body=cipherfile,
        media_mime_type='application/octet-stream'
    ).execute()

    os.remove(cipherfile)


def retrieve(bucket, infile, outfile):
    """
    Retrieves the input file from the specified bucket, decrypts it using the KMS key specified by
    the object metadata, and stores it at the given output path.

    Args:
        1. bucket - GCS bucket containing encrypted file
        2. infile - Path relative to the bucket of the file that should be retrieved and decrypted
        3. outfile - Local output path at which the decrypted file should be stored

    Returns:
        None. Throws an error if something went wrong.
    """
    storage_client = googleapiclient.discovery.build('storage', 'v1')

    kms_client = googleapiclient.discovery.build('cloudkms', 'v1')
    kms_decrypt = kms_client.projects().locations().keyRings().cryptoKeys().decrypt

    # Build KMS key specification from object metadata. This is how we know which key to use to
    # decrypt the encrypted object in GCS.
    metadata = storage_client.objects().get(bucket=bucket, object=infile).execute()
    custom_metadata = metadata['metadata']
    kms_project = custom_metadata['kms-project']
    kms_location = custom_metadata['kms-location']
    kms_keyring = custom_metadata['kms-keyring']
    kms_key = custom_metadata['kms-key']
    route = 'projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}'.format(
        kms_project,
        kms_location,
        kms_keyring,
        kms_key
    )

    # Download the ciphertext from GCS
    ciphertext = storage_client.objects().get_media(bucket=bucket, object=infile).execute()
    ciphertext_b64 = base64.b64encode(ciphertext).decode()

    kms_response = kms_decrypt(name=route, body={'ciphertext': ciphertext_b64}).execute()
    plaintext_b64 = kms_response['plaintext']
    plaintext = base64.b64decode(plaintext_b64)

    with open(outfile, 'wb') as ofp:
        ofp.write(plaintext)


if __name__ == '__main__':
    logger = logging.getLogger('secure-cloud-storage')
    logger.setLevel(logging.INFO)
    log_handler = logging.StreamHandler()
    log_formatter = logging.Formatter('%(levelname)s - %(asctime)s: %(message)s')
    log_handler.setFormatter(log_formatter)
    logger.addHandler(log_handler)


    parser = argparse.ArgumentParser('Secure cloud storage utility')
    parser.add_argument(
        '-b',
        '--bucket',
        help='Google Cloud Storage bucket name'
    )
    parser.add_argument(
        '-i',
        '--infile',
        help=('Path to input file -- if mode is "store", then this should be a local file path, '
            'if mode is "retrieve" it should be a path to a GCS object relative to the bucket')
    )
    parser.add_argument(
        '-o',
        '--outfile',
        help=('Path to output file -- if mode is "store", then this should be a path to a GCS '
            'object relative to the bucket, if mode is "retrieve" it should be a local file path')
    )

    subparsers = parser.add_subparsers(help='sub-commands', dest='mode')

    retrieve_parser = subparsers.add_parser(
        'retrieve',
        help='Retrieve encrypted data from <bucket>/<infile>, decrypt and store it as <outfile>'
    )
    store_parser = subparsers.add_parser(
        'store',
        help='Encrypt data in <infile> using the given KMS key and store it as <bucket>/<outfile>'
    )

    retrieve_parser.add_argument(
        '--overwrite',
        action='store_true',
        help=('Overwrite <outfile> if it already exists. If this flag is not specified and '
            '<outfile> already exists, this program will throw an error')
    )

    store_parser.add_argument(
        '-p',
        '--key-project',
        required=True,
        help='GCP project containing KMS key'
    )
    store_parser.add_argument(
        '-l',
        '--location',
        required=True,
        help='Google Cloud Key Management Service keyring location'
    )
    store_parser.add_argument(
        '-r',
        '--keyring',
        required=True,
        help='Google Cloud Key Management Service keyring name'
    )
    store_parser.add_argument(
        '-k',
        '--key',
        required=True,
        help='Google Cloud Key Management Service key name'
    )
    store_parser.add_argument(
        '-v',
        '--key-version',
        default=None,
        help='Google Cloud Key Management Service key version'
    )

    args = parser.parse_args()


    # Storage JSON API does not like gs:// prefix on bucket names, so let us strip it off if it has
    # been provided
    GCS_PREFIX = 'gs://'
    bucket = args.bucket
    if bucket[:len(GCS_PREFIX)] == GCS_PREFIX:
        bucket = bucket[len(GCS_PREFIX):]

    if args.mode == 'store':
        storage = 'Securely storing input file {} as gs://{}/{}'.format(
            args.infile,
            bucket,
            args.outfile
        )
        encryption = 'Encryption key: {}/{}, keyring: {}, location: {}, project: {}'.format(
            args.key,
            args.key_version,
            args.keyring,
            args.location,
            args.key_project
        )
        message = '{}\n---\n{}'.format(storage, encryption)
        logger.info(message)

        key_spec = (args.key_project, args.location, args.keyring, args.key, args.key_version)
        store(bucket, key_spec, args.infile, args.outfile)
    elif args.mode == 'retrieve':
        message = 'Retrieving file at gs://{}/{} as {}'.format(
            bucket,
            args.infile,
            args.outfile
        )
        logger.info(message)

        if os.path.exists(args.outfile) and not args.overwrite:
            raise Exception('File already exists at output path: {}'.format(args.outfile))
        retrieve(bucket, args.infile, args.outfile)
    else:
        message = 'Unknown subcommand: {}'.format(args.mode)
        logger.error(message)
        raise Exception(message)

    logger.info('Done')