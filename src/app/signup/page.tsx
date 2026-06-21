import SignupForm from "@/components/landing/auth/SignupForm";
import Link from "next/link";

export const metadata = {
    title: "Sign Up | Instagram Clone",
    description: "Create a new account",
};

export default function SignupPage() {
    return (
        <main className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
            <div className="w-full max-w-sm bg-white border border-gray-200 rounded-2xl shadow-sm p-8 space-y-6">
                <div className="text-center">
                    <h1 className="text-2xl font-bold tracking-tight text-gray-800">Create an account</h1>
                    <p className="text-sm text-gray-500 mt-1">Join us today</p>
                </div>

                <SignupForm />

                <p className="text-center text-sm text-gray-500">
                    Already have an account?{" "}
                    <Link href="/login" className="text-purple-600 font-medium hover:underline">
                        Log in
                    </Link>
                </p>
            </div>
        </main>
    );
}
