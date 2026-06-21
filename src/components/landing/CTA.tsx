import Link from "next/link";


export default function CTA() {
  return (
    <section className="py-20 bg-gradient-to-r from-purple-500 via-pink-500 to-orange-500 text-white text-center">
      <h2 className="text-3xl md:text-4xl font-bold">
        Ready to get started?
      </h2>

      <div className="mt-8 flex justify-center gap-4">
        <Link href="/signup" className="px-6 py-3 bg-white text-black rounded-xl font-semibold shadow-md hover:bg-gray-100 transition ">
        Create Account
        </Link>

        <Link href="/login" className="px-6 py-3 bg-white-300 border-2 rounded-xl font-semibold shadow-md hover:bg-white/30 transition">
        Login
        </Link>

      </div>

    </section>
  );
}
