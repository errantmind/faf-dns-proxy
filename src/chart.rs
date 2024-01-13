/// Generate a chart of the latencies.
#[inline]
pub fn _generate_linear_chart(latencies: Vec<u64>) -> anyhow::Result<(), Box<dyn std::error::Error>> {
   assert!(!latencies.is_empty());

   // The latencies must already be sorted.
   let max_value = *latencies.last().unwrap();
   let mut range_size: u64 = 5;
   let get_num_ranges = |max_value: u64, range_size: u64| (max_value / range_size) as usize + 1;

   while get_num_ranges(max_value, range_size) > 10 {
      range_size *= 2;
   }
   let num_ranges = get_num_ranges(max_value, range_size);

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
   let file_path = get_chart_file_path()?;
   renderer.save(&chart, &file_path).map_err(|e| anyhow::anyhow!("{:?}", e))?;
   println!("chart saved to {:?}", &file_path);

   Ok(())
}

#[inline]
pub fn generate_log_chart(latencies: Vec<u64>) -> anyhow::Result<(), Box<dyn std::error::Error>> {
   assert!(!latencies.is_empty());

   // The latencies must already be sorted.
   let max_value = *latencies.last().unwrap();

   // gets the number of ranges using log base 2
   let get_num_ranges = |max_value: u64| fast_log_2(max_value) as usize;

   // Add 2 to the number of ranges to account for the 0ms and max_value ms ranges
   let num_ranges = get_num_ranges(max_value) + 2;

   let mut counts = vec![0; num_ranges];

   for &value in &latencies {
      // Determine which range the value falls into based on its value
      let range_index = fast_log_2(value) as usize;

      if value == 0 {
         counts[0] += 1;
      } else {
         counts[range_index + 1] += 1;
      }
   }

   let mut range_labels = vec![];
   range_labels.push("0ms".to_string());
   range_labels.extend((0..(num_ranges - 1)).map(|i| format!("[{},{}ms)", 2u64.pow(i as u32), 2u64.pow(i as u32 + 1))));

   let min_range_index_to_print = counts.iter().position(|&count| count > 0).unwrap();
   let counts_greater_than_zero = counts[min_range_index_to_print..].to_vec();
   let range_labels_greater_than_zero = range_labels[min_range_index_to_print..].to_vec();

   assert_eq!(counts_greater_than_zero.len(), range_labels_greater_than_zero.len());

   let chart = charming::Chart::new()
      .title(
         charming::component::Title::new().text("Latency Distribution").left("center").subtext("timed: question -> answer").left("center"),
      )
      .x_axis(charming::component::Axis::new().type_(charming::element::AxisType::Category).data(range_labels_greater_than_zero))
      .y_axis(charming::component::Axis::new().type_(charming::element::AxisType::Value).name("count"))
      .series(charming::series::Bar::new().data(counts_greater_than_zero));

   let mut renderer = charming::HtmlRenderer::new("latency distribution", 1920, 720);

   // Save the chart as HTML file.
   let file_path = get_chart_file_path()?;
   renderer.save(&chart, &file_path).map_err(|e| anyhow::anyhow!("{:?}", e))?;
   println!("chart saved to {:?}", &file_path);

   Ok(())
}

#[inline]
pub fn get_chart_file_path() -> anyhow::Result<std::path::PathBuf> {
   let mut file_path = crate::statics::ARGS.data_directory.clone().unwrap_or_else(std::env::temp_dir);
   file_path.push("faf-charts");
   std::fs::create_dir_all(&file_path)?;
   file_path.push("latency-distribution.html");
   Ok(file_path)
}

#[inline]
fn fast_log_2(x: u64) -> u64 {
   if x == 0 {
      return 0;
   }
   let mut y = 0;
   let mut x = x;

   while x > 1 {
      x >>= 1;
      y += 1;
   }

   y
}

#[test]
// test generate_log_chart: 1000 u64 values with a min of 0 and a max of 2000
pub fn test_generate_log_chart() {
   use std::iter::repeat_with;

   let mut latencies: Vec<u64> = repeat_with(|| fastrand::u64(0..64)).take(10000).collect();
   latencies.push(0);
   latencies.push(64);
   latencies.sort_unstable();

   generate_log_chart(latencies).unwrap();
}
