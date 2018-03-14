/*
 * general
 */

/** Class representing a JSON Web Token */
export declare class JWT {
    header: any;
    payload: any;
    signature: any;
}

/** Class representing a JWT header */
export declare class JWTHeader {
    typ: string;
    alg: string;
}



/*
 * from './signer'
 */

/** Class for signing JWTs with a specific configuration */
export class TokenSigner {
    /**
     * Creates a TokenSigner based on a signing algorithm and a private key
     * 
     * @param signingAlgorithm The signing algorithm to base the TokenSigner on (see https://github.com/blockstack/jsontokens-js/blob/master/src/cryptoClients/index.js for supported algorithms)
     * @param rawPrivateKey The private key to base the TokenSigner on
     */
    constructor(signingAlgorithm: string, rawPrivateKey: string);

    /**
     * Returns the header of the yet-to-build JWT
     * 
     * @returns A JWT header
     */
    header(): JWTHeader;

    /**
     * Returns a signed JWT based on a given payload
     * 
     * @param payload The payload for the JWT
     * @param expanded Determines the return value (string on false, otherwise a JWT object)
     * @returns A signed JWT (either represented by a string or a JWT object)
     */
    sign(payload: any, expanded: boolean): string|JWT;
}

/**
 * Creates an unsecured (unsigned) JWT (represented as a string)
 * 
 * @param payload The payload to include into the JWT
 * @returns An unsecured (unsigned) JWT represented as a string
 */
export function createUnsecuredToken(payload: any): string;



/*
 * from './verifier'
 */

/** Class for verifying JWTs with a specific configuration */
export class TokenVerifier {
    /**
     * Creates a TokenVerifier based on a signing algorithm and a public key
     * 
     * @param signingAlgorithm The signing algorithm to base the TokenVerifier on (see https://github.com/blockstack/jsontokens-js/blob/master/src/cryptoClients/index.js for supported algorithms)
     * @param rawPublicKey The public key to base the TokenVerifier on
     */
    constructor(signingAlgorithm: string, rawPublicKey: string);

    /**
     * Verifies a given JWT (represented as string or an JWT object)
     * 
     * @param token The JWT to verify (either as string or as JWT object)
     * @returns A boolean whether the JWT is valid
    */
    verify(token: string|JWT): boolean;
}



/*
 * from './decode'
 */

/**
 * Decodes a string (or the parts of a JWT) into a JWT
 * 
 * @param token The JWT to decode (either as string or as JWT object)
 * @returns The decoded JWT
 */
export function decodeToken(token: string|JWT): JWT;



/*
 * from './errors'
 */

/** Class representing an error for missing parameters */
export declare class MissingParametersError extends Error {
    /**
     * Constructor for creating a new MissingParametersError
     * 
     * @param message The message to create the error with (optional)
     */
    constructor(message?: string);
}

/** Class representing an error for invalid token */
export declare class InvalidTokenError extends Error {
    /**
     * Constructor for creating a new InvalidTokenError
     * 
     * @param message The message to create the error with (optional)
     * */
    constructor(message?: string);
}



/*
 * from './cryptoClients'
 */

/**
 * Class for performing crypto operations with curve secp256k1
 * 
 * (types in here are undocumented mainly because there are no type
 * declarations for the library it's based on, namely 'elliptic',
 * also probably nobody wants to use this class standalone)
 */
export declare class SECP256K1Client {
    /** The algorithm name (fixed to 'ES256K' for curve secp256k1) */
    static algorithmName: string;

    /** Client for curve secp256k1 from the package 'elliptic' (for further usage information see the respective package) */
    static ec: any;

    /** Key encoder from the package 'key-encoder' (for further usage information see the respective package) */
    static keyEncoder: any;

    static createHash(signingInput: any): any;

    static derivePublicKey(privateKey: any, compressed: any): any;

    static encodePublicKey(publicKey: any, originalFormat: any, destinationFormat: any): any;

    static loadPrivateKey(rawPrivateKey: any): any;

    static loadPublicKey(rawPublicKey: any): any;

    static loadSignature(joseSignature: any): any;

    static signHash(signingInputHash: any, rawPrivateKey: any, format?: any): any;

    static verifyHash(signingInputHash: any, derSignatureBuffer: any, rawPublicKey: any): any;
}

/** Class for all implemented crypto clients */
declare class cryptoClients {
    ES256K: SECP256K1Client;
}
