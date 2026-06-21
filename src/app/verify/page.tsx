import { Suspense } from "react";
import OTPForm from "@/components/landing/auth/OTPForm";

export const metadata = {
    title: "Verify OTP | Instagram Clone",
    description: "Enter the OTP sent to your email",
};

export default function VerifyPage() {
    return (
        <main className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
            <div className="w-full max-w-sm bg-white border border-gray-200 rounded-2xl shadow-sm p-8 space-y-6">
                <div className="text-center">
                    <h1 className="text-2xl font-bold tracking-tight text-gray-800">Check your email</h1>
                    <p className="text-sm text-gray-500 mt-1">
                        We sent a 6-digit code to your email address
                    </p>
                </div>

                {/*
                    OTPForm uses useSearchParams() which requires a Suspense boundary
                    when rendered inside a Server Component page.
                */}
                <Suspense fallback={<p className="text-center text-sm text-gray-400">Loading...</p>}>
                    <OTPForm />
                </Suspense>
            </div>
        </main>
    );
}
