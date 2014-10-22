#include <pebble.h>
#include "lodepng_encode.h"
#include <stdio.h>
#include <stdlib.h>
	
Window *window;	

static TextLayer *s_time_layer;
static char time_text[] = "00:00:00";

static bool is_encoding = false;
	
// Key values for AppMessage Dictionary
enum {
	STATUS_KEY = 0,	
	MESSAGE_KEY = 1
};
	
static uint8_t* imagedata;

static void bmpData(GBitmap *bmp) {
	  imagedata = malloc(bmp->row_size_bytes * bmp->bounds.size.h);
    for (int i=0; i<bmp->row_size_bytes*bmp->bounds.size.h; i++) {
	     imagedata[i] = ((uint8_t *)bmp->addr)[i];
    }	
}

void png_encode(const unsigned char* image)
{
  unsigned char* png;
  size_t pngsize;

  unsigned error = lodepng_encode_memory(&png, &pngsize, image, 144, 168, LCT_GREY, 1);

	APP_LOG(APP_LOG_LEVEL_DEBUG, "PNG Encode Error: %d", error);

  free(png);	
}

static void handle_tick(struct tm *tick_time, TimeUnits units_changed) {
	if(clock_is_24h_style()) {
		strftime(time_text, sizeof(time_text), "%H:%M:%S", tick_time);
	}
	else {
		strftime(time_text, sizeof(time_text), "%I:%M:%S", tick_time);	
		if (time_text[0] == '0') {
			memmove(&time_text[0], &time_text[1], sizeof(time_text) - 1); //remove leading zero
		}
	}    
	text_layer_set_text(s_time_layer, time_text);
}

static void bg_update_proc(Layer *layer, GContext *ctx) {
	if(!is_encoding) {
		is_encoding = true;
		GBitmap *fb = graphics_capture_frame_buffer(ctx); 
		APP_LOG(APP_LOG_LEVEL_DEBUG, "Captured framebuffer");
		bmpData(fb);	
		APP_LOG(APP_LOG_LEVEL_DEBUG, "Converted bitmap");
		png_encode((const unsigned char*)imagedata);	
		APP_LOG(APP_LOG_LEVEL_DEBUG, "Encoded PNG");
		graphics_release_frame_buffer(ctx, fb); 
		APP_LOG(APP_LOG_LEVEL_DEBUG, "Released framebuffer");	
		//is_encoding = false;
	}

}

void init(void) {
	window = window_create();
	window_stack_push(window, true);
	
  s_time_layer = text_layer_create(GRect(0, 15, 144, 40));
  text_layer_set_background_color(s_time_layer, GColorBlack);
  text_layer_set_text_color(s_time_layer, GColorWhite);
  text_layer_set_text(s_time_layer, "00:00:00");
  text_layer_set_text_alignment(s_time_layer, GTextAlignmentCenter);
  text_layer_set_font(s_time_layer, fonts_get_system_font(FONT_KEY_ROBOTO_CONDENSED_21));
  layer_add_child(window_get_root_layer(window), (Layer *)s_time_layer);	
	
	//Somebody set us up the CLOCK
	time_t now = time(NULL);
	struct tm *tick_time = localtime(&now);  

	handle_tick(tick_time, SECOND_UNIT);
	//tick_timer_service_subscribe(SECOND_UNIT, handle_tick);	
	
  Layer *window_layer = window_get_root_layer(window);
	layer_set_update_proc(window_layer, bg_update_proc);
	
	// Register AppMessage handlers
	//app_message_register_inbox_received(in_received_handler); 
	//app_message_register_inbox_dropped(in_dropped_handler); 
	//app_message_register_outbox_failed(out_failed_handler);
		
	//app_message_open(app_message_inbox_size_maximum(), app_message_outbox_size_maximum());
	
	//send_message();
}

void deinit(void) {
	app_message_deregister_callbacks();
	window_destroy(window);
}

int main( void ) {
	init();
	app_event_loop();
	deinit();
}

/*

// Write message to buffer & send
void send_message(void){
	DictionaryIterator *iter;
	
	app_message_outbox_begin(&iter);
	dict_write_uint8(iter, STATUS_KEY, 0x1);
	
	dict_write_end(iter);
  	app_message_outbox_send();
}

// Called when a message is received from PebbleKitJS
static void in_received_handler(DictionaryIterator *received, void *context) {
	Tuple *tuple;
	
	tuple = dict_find(received, STATUS_KEY);
	if(tuple) {
		APP_LOG(APP_LOG_LEVEL_DEBUG, "Received Status: %d", (int)tuple->value->uint32); 
	}
	
	tuple = dict_find(received, MESSAGE_KEY);
	if(tuple) {
		APP_LOG(APP_LOG_LEVEL_DEBUG, "Received Message: %s", tuple->value->cstring);
	}}

// Called when an incoming message from PebbleKitJS is dropped
static void in_dropped_handler(AppMessageResult reason, void *context) {	
}

// Called when PebbleKitJS does not acknowledge receipt of a message
static void out_failed_handler(DictionaryIterator *failed, AppMessageResult reason, void *context) {
}
*/