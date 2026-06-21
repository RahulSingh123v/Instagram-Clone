import { Camera, Heart, Shield } from "lucide-react";

const features = [
  {
    icon: Camera,
    title: "Share Photos",
    description: "Upload and post instantly.",
  },
  {
    icon: Heart,
    title: "Engage",
    description: "Like, comment, and connect.",
  },
  {
    icon: Shield,
    title: "Secure",
    description: "Safe authentication & privacy.",
  },
];

export default function Features() {
  return (
    <section className="py-20 bg-white">
      <div className="max-w-6xl mx-auto px-6 grid md:grid-cols-3 gap-8">
        {features.map((feature, i) => {
          const Icon = feature.icon;
          return (
            <div
              key={i}
              className="p-8 rounded-2xl border border-gray-200 shadow-sm hover:shadow-lg transition"
            >
              <Icon className="w-8 h-8 text-purple-600" />
              <h3 className="mt-4 text-xl text-gray-600 font-semibold">{feature.title}</h3>
              <p className="mt-2 text-gray-600">{feature.description}</p>
            </div>
          );
        })}
      </div>
    </section>
  );
}