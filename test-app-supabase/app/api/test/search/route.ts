import { NextRequest, NextResponse } from 'next/server'

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') || ''
  return NextResponse.json({
    success: true,
    message: 'Search request passed through middleware',
    query: q,
    results: [],
  })
}
