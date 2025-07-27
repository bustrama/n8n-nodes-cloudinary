import { IDataObject } from 'n8n-workflow';
import { sha256 } from './sha256.utils';

/**
 * Generate Cloudinary signature for signed uploads
 */
export const generateCloudinarySignature = (params: IDataObject, apiSecret: string): string => {
	// Remove signature, api_key, and file from params for signature generation
	const { signature, api_key, file, ...paramsToSign } = params;

	// Sort parameters alphabetically and create query string
	const sortedParams = Object.keys(paramsToSign)
		.sort()
		.map((key) => `${key}=${paramsToSign[key]}`)
		.join('&');

	// Append API secret
	const stringToSign = `${sortedParams}${apiSecret}`;

	// Generate SHA1 hash using pure JavaScript implementation
	return sha256(stringToSign);
}

/**
 * Create multipart form data without external dependencies
 */
export const createMultipartBody = (fields: Record<string, string>, fileData: Buffer, fileName: string, mimeType: string): { body: Buffer; boundary: string } => {
	const boundary = `----formdata-n8n-${Math.random().toString(16).slice(2)}`;
	const CRLF = '\r\n';
	
	let body = '';
	
	// Add text fields
	for (const [name, value] of Object.entries(fields)) {
		body += `--${boundary}${CRLF}`;
		body += `Content-Disposition: form-data; name="${name}"${CRLF}`;
		body += CRLF;
		body += value;
		body += CRLF;
	}
	
	// Add file field
	body += `--${boundary}${CRLF}`;
	body += `Content-Disposition: form-data; name="file"; filename="${fileName}"${CRLF}`;
	body += `Content-Type: ${mimeType}${CRLF}`;
	body += CRLF;
	
	// Convert string part to buffer and concatenate with file data
	const textBuffer = Buffer.from(body, 'utf8');
	const endBuffer = Buffer.from(`${CRLF}--${boundary}--${CRLF}`, 'utf8');
	
	const finalBody = Buffer.concat([textBuffer, fileData, endBuffer]);
	
	return { body: finalBody, boundary };
} 