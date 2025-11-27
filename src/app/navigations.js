const navigations = [
  { name: "Page 1", path: "/dashboard/default", icon: "dashboard" },
  { label: "PAGES", type: "label" },
  {
    name: "Page 2",
    icon: "trending_up",
    children: [
      { name: "Dummy Page 1", path: "/dummy1", iconText: "D1" },
      { name: "Dummy Page 2", path: "/dummy2", iconText: "D2" }
    ]
  }
];

export default navigations;
