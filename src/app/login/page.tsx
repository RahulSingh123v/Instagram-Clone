import LoginForm from "@/components/landing/auth/LoginForm";
import Link from "next/link";

export const metadata = {
    title: "Login | Instagram Clone",
    description: "Log in to your account",
};

export default function LoginPage() {
    return (
        <main className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
            <div className="w-full max-w-sm bg-white border border-gray-200 rounded-2xl shadow-sm p-8 space-y-6">
                <div className="text-center">
                    <h1 className="text-2xl font-bold tracking-tight text-gray-900">Welcome back</h1>
                    <p className="text-sm text-gray-500 mt-1">Log in to your account</p>
                </div>

                <LoginForm />

                <p className="text-center text-sm text-gray-500">
                    Don&apos;t have an account?{" "}
                    <Link href="/signup" className="text-purple-600 font-medium hover:underline">
                        Sign up
                    </Link>
                </p>
            </div>
        </main>
    );
}
