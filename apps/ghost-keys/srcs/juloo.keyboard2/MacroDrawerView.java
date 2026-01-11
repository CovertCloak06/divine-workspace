package juloo.keyboard2;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;
import java.util.List;

/**
 * A drawer view that displays saved macros in a grid.
 * Users can tap to insert a macro, long-press to delete.
 */
public class MacroDrawerView extends View
{
  public interface OnMacroActionListener
  {
    void onMacroTap(String command);
    void onMacroLongPress(int index, String label);
    void onDrawerClose();
  }

  private MacroStorage _storage;
  private OnMacroActionListener _listener;
  private Paint _bgPaint;
  private Paint _buttonPaint;
  private Paint _buttonPressedPaint;
  private Paint _textPaint;
  private Paint _headerPaint;
  private Paint _closeButtonPaint;

  private List<MacroStorage.Macro> _macros;
  private int _pressedIndex = -1;
  private long _pressStartTime = 0;
  private static final long LONG_PRESS_TIME = 500;

  private int _columns = 4;
  private float _buttonHeight;
  private float _buttonMargin;
  private float _headerHeight;
  private int _scrollOffset = 0;

  // Colors matching PKN theme
  private static final int COLOR_BG = 0xF0101010;
  private static final int COLOR_BUTTON = 0xFF1A1A1A;
  private static final int COLOR_BUTTON_PRESSED = 0xFF00FFFF;
  private static final int COLOR_TEXT = 0xFFE0E0E0;
  private static final int COLOR_HEADER = 0xFF00FFFF;
  private static final int COLOR_BORDER = 0xFF333333;

  public MacroDrawerView(Context context)
  {
    super(context);
    init(context);
  }

  public MacroDrawerView(Context context, AttributeSet attrs)
  {
    super(context, attrs);
    init(context);
  }

  private void init(Context context)
  {
    _storage = new MacroStorage(context);

    _bgPaint = new Paint();
    _bgPaint.setColor(COLOR_BG);
    _bgPaint.setStyle(Paint.Style.FILL);

    _buttonPaint = new Paint();
    _buttonPaint.setColor(COLOR_BUTTON);
    _buttonPaint.setStyle(Paint.Style.FILL);

    _buttonPressedPaint = new Paint();
    _buttonPressedPaint.setColor(COLOR_BUTTON_PRESSED);
    _buttonPressedPaint.setStyle(Paint.Style.FILL);

    _textPaint = new Paint();
    _textPaint.setColor(COLOR_TEXT);
    _textPaint.setTextAlign(Paint.Align.CENTER);
    _textPaint.setAntiAlias(true);
    _textPaint.setTypeface(Typeface.DEFAULT_BOLD);

    _headerPaint = new Paint();
    _headerPaint.setColor(COLOR_HEADER);
    _headerPaint.setTextAlign(Paint.Align.CENTER);
    _headerPaint.setAntiAlias(true);
    _headerPaint.setTypeface(Typeface.DEFAULT_BOLD);

    _closeButtonPaint = new Paint();
    _closeButtonPaint.setColor(COLOR_HEADER);
    _closeButtonPaint.setStyle(Paint.Style.STROKE);
    _closeButtonPaint.setStrokeWidth(3);
    _closeButtonPaint.setAntiAlias(true);

    refreshMacros();
  }

  public void setListener(OnMacroActionListener listener)
  {
    _listener = listener;
  }

  public void refreshMacros()
  {
    _macros = _storage.getMacros();
    invalidate();
  }

  public MacroStorage getStorage()
  {
    return _storage;
  }

  @Override
  protected void onSizeChanged(int w, int h, int oldw, int oldh)
  {
    super.onSizeChanged(w, h, oldw, oldh);
    _buttonHeight = h * 0.15f;
    _buttonMargin = w * 0.02f;
    _headerHeight = h * 0.12f;
    _textPaint.setTextSize(_buttonHeight * 0.35f);
    _headerPaint.setTextSize(_headerHeight * 0.5f);
  }

  @Override
  protected void onDraw(Canvas canvas)
  {
    super.onDraw(canvas);

    int w = getWidth();
    int h = getHeight();

    // Draw background
    canvas.drawRect(0, 0, w, h, _bgPaint);

    // Draw header
    canvas.drawText("Saved Macros", w / 2f, _headerHeight * 0.65f, _headerPaint);

    // Draw close button (X) in top right
    float closeX = w - _headerHeight * 0.5f;
    float closeY = _headerHeight * 0.5f;
    float closeSize = _headerHeight * 0.25f;
    canvas.drawLine(closeX - closeSize, closeY - closeSize,
                    closeX + closeSize, closeY + closeSize, _closeButtonPaint);
    canvas.drawLine(closeX + closeSize, closeY - closeSize,
                    closeX - closeSize, closeY + closeSize, _closeButtonPaint);

    // Draw macro count
    _headerPaint.setTextSize(_headerHeight * 0.3f);
    canvas.drawText(_macros.size() + " macros (tap=insert, hold=delete)",
                    w / 2f, _headerHeight * 0.95f, _headerPaint);
    _headerPaint.setTextSize(_headerHeight * 0.5f);

    if (_macros.isEmpty())
    {
      _textPaint.setTextSize(_buttonHeight * 0.4f);
      canvas.drawText("No macros saved yet", w / 2f, h / 2f, _textPaint);
      canvas.drawText("Use the + button to save commands", w / 2f, h / 2f + _buttonHeight * 0.5f, _textPaint);
      _textPaint.setTextSize(_buttonHeight * 0.35f);
      return;
    }

    // Draw macro buttons in grid
    float buttonWidth = (w - _buttonMargin * (_columns + 1)) / _columns;
    float startY = _headerHeight + _buttonMargin;

    for (int i = 0; i < _macros.size(); i++)
    {
      int col = i % _columns;
      int row = i / _columns;

      float x = _buttonMargin + col * (buttonWidth + _buttonMargin);
      float y = startY + row * (_buttonHeight + _buttonMargin) - _scrollOffset;

      // Skip if off screen
      if (y + _buttonHeight < _headerHeight || y > h)
        continue;

      RectF rect = new RectF(x, y, x + buttonWidth, y + _buttonHeight);

      // Draw button
      Paint paint = (i == _pressedIndex) ? _buttonPressedPaint : _buttonPaint;
      canvas.drawRoundRect(rect, 8, 8, paint);

      // Draw border
      Paint borderPaint = new Paint();
      borderPaint.setColor(COLOR_BORDER);
      borderPaint.setStyle(Paint.Style.STROKE);
      borderPaint.setStrokeWidth(2);
      canvas.drawRoundRect(rect, 8, 8, borderPaint);

      // Draw label
      MacroStorage.Macro macro = _macros.get(i);
      float textY = y + _buttonHeight / 2f + _textPaint.getTextSize() / 3f;

      // Truncate label if too long
      String label = macro.label;
      if (label.length() > 8)
        label = label.substring(0, 7) + "…";

      if (i == _pressedIndex)
        _textPaint.setColor(0xFF000000);
      else
        _textPaint.setColor(COLOR_TEXT);

      canvas.drawText(label, x + buttonWidth / 2f, textY, _textPaint);
    }

    _textPaint.setColor(COLOR_TEXT);
  }

  @Override
  public boolean onTouchEvent(MotionEvent event)
  {
    float x = event.getX();
    float y = event.getY();

    switch (event.getAction())
    {
      case MotionEvent.ACTION_DOWN:
        // Check close button
        if (y < _headerHeight && x > getWidth() - _headerHeight)
        {
          if (_listener != null)
            _listener.onDrawerClose();
          return true;
        }

        // Find which button was pressed
        _pressedIndex = getButtonIndex(x, y);
        _pressStartTime = System.currentTimeMillis();
        invalidate();
        return true;

      case MotionEvent.ACTION_MOVE:
        int newIndex = getButtonIndex(x, y);
        if (newIndex != _pressedIndex)
        {
          _pressedIndex = -1;
          invalidate();
        }
        return true;

      case MotionEvent.ACTION_UP:
        if (_pressedIndex >= 0 && _pressedIndex < _macros.size())
        {
          long pressDuration = System.currentTimeMillis() - _pressStartTime;
          if (pressDuration >= LONG_PRESS_TIME)
          {
            // Long press - delete
            if (_listener != null)
              _listener.onMacroLongPress(_pressedIndex, _macros.get(_pressedIndex).label);
          }
          else
          {
            // Short tap - insert
            if (_listener != null)
              _listener.onMacroTap(_macros.get(_pressedIndex).command);
          }
        }
        _pressedIndex = -1;
        invalidate();
        return true;

      case MotionEvent.ACTION_CANCEL:
        _pressedIndex = -1;
        invalidate();
        return true;
    }

    return super.onTouchEvent(event);
  }

  private int getButtonIndex(float x, float y)
  {
    if (y < _headerHeight)
      return -1;

    float buttonWidth = (getWidth() - _buttonMargin * (_columns + 1)) / _columns;
    float startY = _headerHeight + _buttonMargin;

    int col = (int) ((x - _buttonMargin) / (buttonWidth + _buttonMargin));
    int row = (int) ((y - startY + _scrollOffset) / (_buttonHeight + _buttonMargin));

    if (col < 0 || col >= _columns)
      return -1;

    int index = row * _columns + col;
    if (index < 0 || index >= _macros.size())
      return -1;

    return index;
  }
}
