import { NextResponse } from "next/server";
import { NextRequest } from "next/server";

const PUBLIC_ROUTES = [
    "/",
    "/login",
    "/signup",
    "/verify",
];

const AUTH_ROUTES = [
    "/login",
    "/signup",
    "/verify",

];

export function middleware(request: NextRequest){

    const { pathname } = request.nextUrl;

    const accessToken = request.cookies.get("access_token")?.value;

    const isPublicRoute= PUBLIC_ROUTES.some(
        (route) => 
            pathname === route || 
            pathname.startsWith(`${route}/`)
    );

    const isAuthRoute = AUTH_ROUTES.some(
        (route) =>
            pathname === route ||
        pathname.startsWith(`${route}/`)
    );

    if (!accessToken && !isAuthRoute){
        return NextResponse.redirect(
            new URL("/login",request.url)
        );
    }

    if (accessToken && isAuthRoute){
        return NextResponse.redirect(
            new URL("/dashboard",request.url)
        );
    }
    return NextResponse.next();
}

export const config = {
    matcher: [
        "/dashboard/:path*",
        "/profile/:path*",
        "/settings/:path*",
        "/login",
        "/signup",
        "/verify"
    ]
}