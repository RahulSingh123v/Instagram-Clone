import Link from "next/link";

export default function Navbar() {
  return (
    <header className="w-full border-b border-gray-100 bg-white/95 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
            <Link href="/" className=" text-gray-600 text-2xl font-semibold">
            Instagram
            </Link>
            <div className="flex items-center gap-6">
                <Link href="/login" className=" text-gray-600 hover:text-black transition" >
                Login
                </Link>
                <Link href="/signup" className="px-4 py-2 rounded-lg bg-linear-to-r from-orange-500 to-purple-500 text-white font-medium shadow-md hover:opacity-80 transition">
                Create Account
                </Link>
            </div>
        </div>
    </header>
  );
}
