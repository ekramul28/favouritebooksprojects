import { NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function GET() {
  const books = await prisma.book.findMany();
  return NextResponse.json(books);
}
