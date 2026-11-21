import { presignResponseSchema } from "@mono/auth";
import { AppError } from "../errors.js";
import { MESSAGES } from "../messages.js";
import { createPresigner } from "../presign.js";

const presigner = createPresigner({
  bucket: "uploads-bucket",
  region: "ap-southeast-3",
  credentials: { accessKeyId: "AKIAFAKE", secretAccessKey: "fake-secret" },
});
const PDF = {
  contentType: "application/pdf",
  maxBytes: 5_000_000,
  allowedTypes: ["application/pdf"],
};

async function caught(promise: Promise<unknown>) {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(AppError);
  return error as AppError;
}

describe("createPresigner", () => {
  it("returns the presign shape @mono/auth parses", async () => {
    const res = await presigner.presign({ ...PDF, filename: "my file?.pdf", size: 1000 });
    expect(presignResponseSchema.safeParse(res).success).toBe(true);
    expect(res.s3_key).toMatch(/^uploads\/[0-9a-f-]{36}\/my_file_\.pdf$/);
    expect(res.s3_key).toContain(res.upload_uuid);
    expect(res.presign_url).toContain("uploads-bucket");
  });

  it("binds content type and size range into the signed policy", async () => {
    const res = await presigner.presign({ ...PDF, filename: "a.pdf", size: 10 });
    expect(res.fields?.["Content-Type"]).toBe("application/pdf");
    const policy = JSON.parse(Buffer.from(String(res.fields?.Policy), "base64").toString());
    expect(policy.conditions).toEqual(
      expect.arrayContaining([
        ["content-length-range", 1, 5_000_000],
        { "Content-Type": "application/pdf" },
      ])
    );
  });

  it("rejects oversized, empty and disallowed files with 422", async () => {
    const big = await caught(presigner.presign({ ...PDF, filename: "a.pdf", size: 5_000_001 }));
    expect(big).toMatchObject({ code: 422, message: MESSAGES.fileTooLarge });
    expect((await caught(presigner.presign({ ...PDF, filename: "a.pdf", size: 0 }))).code).toBe(
      422
    );
    const type = await caught(
      presigner.presign({ ...PDF, contentType: "text/html", filename: "a.html", size: 10 })
    );
    expect(type).toMatchObject({ code: 422, message: MESSAGES.fileTypeNotAllowed });
  });

  it("never lets a filename add path segments", async () => {
    const res = await presigner.presign({ ...PDF, filename: "../../etc/passwd", size: 10 });
    const [, , name] = (res.s3_key as string).split("/");
    expect((res.s3_key as string).split("/")).toHaveLength(3);
    expect(name).toBe(".._.._etc_passwd");
  });

  it("truncates long names and falls back for names with nothing usable", async () => {
    const long = await presigner.presign({ ...PDF, filename: `${"a".repeat(300)}.pdf`, size: 10 });
    expect((long.s3_key as string).split("/")[2]).toHaveLength(100);
    const empty = await presigner.presign({ ...PDF, filename: "", size: 10 });
    expect((empty.s3_key as string).split("/")[2]).toBe("file");
  });

  it("supports an S3-compatible endpoint (MinIO), a key prefix and expiry", async () => {
    const minio = createPresigner({
      bucket: "dev",
      region: "us-east-1",
      endpoint: "http://localhost:9000",
      forcePathStyle: true,
      credentials: { accessKeyId: "minio", secretAccessKey: "minio123" },
      keyPrefix: "attachments",
      expiresInSeconds: 60,
    });
    const res = await minio.presign({ ...PDF, filename: "a.pdf", size: 10 });
    expect(res.presign_url).toBe("http://localhost:9000/dev");
    expect(res.s3_key).toMatch(/^attachments\//);
    const policy = JSON.parse(Buffer.from(String(res.fields?.Policy), "base64").toString());
    const expires = new Date(policy.expiration).getTime() - Date.now();
    expect(expires).toBeLessThanOrEqual(60_000);
    expect(expires).toBeGreaterThan(50_000);
  });
});
