import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { presignResponseSchema } from "@mono/auth";
import { AppError } from "../errors.js";
import { MESSAGES } from "../messages.js";
import { createPresigner } from "../presign.js";

vi.mock("@aws-sdk/s3-request-presigner", () => ({
  getSignedUrl: vi.fn(async () => "https://signed.example/get"),
}));

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

describe("presigner.presignDownload", () => {
  beforeEach(() => vi.mocked(getSignedUrl).mockClear());

  it("signs a GET with an attachment disposition and the default expiry", async () => {
    const res = await presigner.presignDownload({
      key: "uploads/u/a.pdf",
      filename: "Laporan Q1.pdf",
    });
    expect(res).toEqual({ url: "https://signed.example/get", expires_in: 300 });
    const [, command, options] = vi.mocked(getSignedUrl).mock.calls[0] as unknown as [
      unknown,
      GetObjectCommand,
      { expiresIn: number },
    ];
    expect(command).toBeInstanceOf(GetObjectCommand);
    expect(command.input).toMatchObject({
      Bucket: "uploads-bucket",
      Key: "uploads/u/a.pdf",
      ResponseContentDisposition: 'attachment; filename="Laporan Q1.pdf"',
    });
    expect(options.expiresIn).toBe(300);
  });

  it("honours expiresInSeconds and strips quotes, backslashes and control characters", async () => {
    const res = await presigner.presignDownload({
      key: "k",
      filename: 'a"b\\c\r\nd\x00e\x7ff.pdf',
      expiresInSeconds: 60,
    });
    expect(res.expires_in).toBe(60);
    const [, command, options] = vi.mocked(getSignedUrl).mock.calls[0] as unknown as [
      unknown,
      GetObjectCommand,
      { expiresIn: number },
    ];
    expect(command.input.ResponseContentDisposition).toBe('attachment; filename="abcdef.pdf"');
    expect(options.expiresIn).toBe(60);
  });
});

describe("presigner.stat", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns size and content type from HeadObject", async () => {
    const send = vi.spyOn(S3Client.prototype, "send").mockImplementation((async () => ({
      ContentLength: 10,
      ContentType: "application/pdf",
    })) as never);
    expect(await presigner.stat("uploads/u/a.pdf")).toEqual({
      size: 10,
      contentType: "application/pdf",
    });
    const command = send.mock.calls[0]?.[0] as { input: unknown };
    expect(command.input).toEqual({ Bucket: "uploads-bucket", Key: "uploads/u/a.pdf" });
  });

  it("falls back to 0 and octet-stream when the headers are missing", async () => {
    vi.spyOn(S3Client.prototype, "send").mockImplementation((async () => ({})) as never);
    expect(await presigner.stat("k")).toEqual({
      size: 0,
      contentType: "application/octet-stream",
    });
  });

  it("returns null for NotFound and 404 errors", async () => {
    const send = vi.spyOn(S3Client.prototype, "send");
    send.mockRejectedValueOnce(Object.assign(new Error("nf"), { name: "NotFound" }));
    expect(await presigner.stat("k")).toBeNull();
    send.mockRejectedValueOnce(
      Object.assign(new Error("nf"), { $metadata: { httpStatusCode: 404 } })
    );
    expect(await presigner.stat("k")).toBeNull();
  });

  it("rethrows any other error", async () => {
    const boom = Object.assign(new Error("denied"), { $metadata: { httpStatusCode: 403 } });
    vi.spyOn(S3Client.prototype, "send").mockRejectedValueOnce(boom);
    await expect(presigner.stat("k")).rejects.toBe(boom);
    vi.spyOn(S3Client.prototype, "send").mockRejectedValueOnce("plain");
    await expect(presigner.stat("k")).rejects.toBe("plain");
  });
});
