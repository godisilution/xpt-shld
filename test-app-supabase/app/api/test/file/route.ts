import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  const filePath = request.nextUrl.searchParams.get('path') || ''
  return NextResponse.json({
    success: true,
    message: 'File request passed through middleware',
    requestedPath: filePath,
  })
}
