import 'package:flutter/material.dart';

class AppController extends ChangeNotifier {
  AppController();

  int _currentIndex = 0;

  int get currentIndex => _currentIndex;

  void setIndex(int index) {
    if (_currentIndex == index) {
      return;
    }
    _currentIndex = index;
    notifyListeners();
  }

  void resetIndex() {
    if (_currentIndex == 0) {
      return;
    }

    _currentIndex = 0;
    notifyListeners();
  }
}
