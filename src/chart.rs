/// Generate a chart of the latencies.
pub fn generate_chart(latencies: Vec<u64>) -> anyhow::Result<(), Box<dyn std::error::Error>> {
   assert!(!latencies.is_empty());

   // The latencies must already be sorted.
   let max_value = latencies.last().unwrap();
   let range_size: u64 = 5;
   let num_ranges = (max_value / range_size) as usize + 1;

   let mut counts = vec![0; num_ranges];
   for &value in &latencies {
      // Determine which range the value falls into based on its value
      let range_index = (value / range_size) as usize;
      counts[range_index] += 1;
   }

   let ranges = (0..num_ranges).map(|i| format!("[{},{})ms", i as u64 * range_size, (i as u64 + 1) * range_size)).collect::<Vec<_>>();

   let chart = charming::Chart::new()
      .title(
         charming::component::Title::new().text("Latency Distribution").left("center").subtext("timed: question -> answer").left("center"),
      )
      .x_axis(charming::component::Axis::new().type_(charming::element::AxisType::Category).data(ranges))
      .y_axis(charming::component::Axis::new().type_(charming::element::AxisType::Value).name("count"))
      .series(charming::series::Bar::new().data(counts));

   let mut renderer = charming::HtmlRenderer::new("latency distribution", 1800, 720);

   // Save the chart as HTML file.
   let mut file_path = crate::statics::ARGS.data_directory.clone().unwrap_or_else(std::env::temp_dir);
   file_path.push("faf-charts");
   std::fs::create_dir_all(&file_path)?;
   file_path.push("latency-distribution.html");
   renderer.save(&chart, &file_path).map_err(|e| anyhow::anyhow!("{:?}", e))?;
   println!("chart saved to {:?}", &file_path);

   Ok(())
}
