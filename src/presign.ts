import { randomUUID } from "node:crypto";
import { S3Client } from "@aws-sdk/client-s3";
import { createPresignedPost } from "@aws-sdk/s3-presigned-post";
import type { PresignResponse } from "@mono/auth";
import { AppError } from "./errors.js";
import { MESSAGES } from "./messages.js";

export type PresignerOptions = {
  bucket: string;
  region: string;
  /** S3-compatible endpoint, e.g. MinIO in local dev. */
  endpoint?: string;
  forcePathStyle?: boolean;
  /** Defaults to the AWS SDK credential chain. */
  credentials?: { accessKeyId: string; secretAccessKey: string };
  /** Default 300 (5 minutes). */
  expiresInSeconds?: number;
  /** Default "uploads". */
  keyPrefix?: string;
};

export type PresignRequest = {
  filename: string;
  contentType: string;
  size: number;
  maxBytes: number;
  allowedTypes: readonly string[];
};

/** Keeps a filename to one safe path segment of at most 100 characters. */
function sanitize(filename: string): string {
  const safe = filename
    .replace(/[^A-Za-z0-9._-]/g, "_")
    .replace(/_+/g, "_")
    .slice(0, 100);
  return safe || "file";
}

/**
 * Presigned S3 POST for browser → storage uploads. The signed policy pins the
 * content type and size range, so storage itself rejects anything else. The
 * returned `upload_uuid` is part of the key; the app's commit endpoint maps it
 * back to `s3_key`.
 */
export function createPresigner(opts: PresignerOptions) {
  const s3 = new S3Client({
    region: opts.region,
    endpoint: opts.endpoint,
    forcePathStyle: opts.forcePathStyle,
    credentials: opts.credentials,
  });
  const prefix = opts.keyPrefix ?? "uploads";
  const expires = opts.expiresInSeconds ?? 300;

  return {
    async presign(p: PresignRequest): Promise<PresignResponse> {
      if (p.size <= 0 || p.size > p.maxBytes) throw new AppError(422, MESSAGES.fileTooLarge);
      if (!p.allowedTypes.includes(p.contentType)) {
        throw new AppError(422, MESSAGES.fileTypeNotAllowed);
      }
      const uploadUuid = randomUUID();
      const key = `${prefix}/${uploadUuid}/${sanitize(p.filename)}`;
      const { url, fields } = await createPresignedPost(s3, {
        Bucket: opts.bucket,
        Key: key,
        Conditions: [["content-length-range", 1, p.maxBytes], { "Content-Type": p.contentType }],
        Fields: { "Content-Type": p.contentType },
        Expires: expires,
      });
      return { upload_uuid: uploadUuid, s3_key: key, presign_url: url, fields };
    },
  };
}
