import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const body = await request.json()
  return NextResponse.json({
    success: true,
    message: 'Comment request passed through middleware',
    contentLength: (body.content || '').length,
  })
}
