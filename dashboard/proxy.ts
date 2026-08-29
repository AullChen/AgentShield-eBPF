import { NextRequest, NextResponse } from "next/server";

const dashboardUser = "agentshield";
const minimumTokenBytes = 24;
const maximumTokenBytes = 512;

export function proxy(request: NextRequest) {
  const expectedToken = process.env.AGENTSHIELD_DASHBOARD_TOKEN ?? "";
  if (!validToken(expectedToken)) {
    return plainResponse("dashboard authentication is unavailable", 503);
  }

  const credentials = basicCredentials(request.headers.get("authorization"));
  if (
    credentials === null ||
    credentials.username !== dashboardUser ||
    !constantTimeEqual(credentials.password, expectedToken)
  ) {
    const response = plainResponse("authentication required", 401);
    response.headers.set(
      "WWW-Authenticate",
      'Basic realm="AgentShield Dashboard", charset="UTF-8"',
    );
    return response;
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};

function basicCredentials(value: string | null) {
  if (value === null || value.length > 1024) return null;
  const match = /^Basic ([A-Za-z0-9+/]+={0,2})$/.exec(value);
  if (match === null) return null;
  try {
    const decoded = atob(match[1]);
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    return {
      username: decoded.slice(0, separator),
      password: decoded.slice(separator + 1),
    };
  } catch {
    return null;
  }
}

function validToken(value: string) {
  const bytes = new TextEncoder().encode(value);
  return (
    bytes.length >= minimumTokenBytes &&
    bytes.length <= maximumTokenBytes &&
    !/[\s\x00-\x1f\x7f]/.test(value)
  );
}

function constantTimeEqual(left: string, right: string) {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  const length = Math.max(leftBytes.length, rightBytes.length);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < length; index += 1) {
    difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
  }
  return difference === 0;
}

function plainResponse(body: string, status: number) {
  return new NextResponse(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
