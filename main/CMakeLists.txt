idf_component_register(
  SRCS
    "app/main.cpp"
  INCLUDE_DIRS
    "."
    "../include"
  REQUIRES esp_timer freertos driver
)